package com.jwt.domain.login.jwt.token;

import com.jwt.domain.login.dto.TokenInfo;
import com.jwt.domain.login.dto.TokenValidationResult;
import com.jwt.domain.login.jwt.blacklist.AccessTokenBlackList;
import com.jwt.domain.member.Member;
import com.jwt.domain.member.UserPrinciple;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Key;
import java.util.*;


@Slf4j
public class TokenProvider { //토큰 생성 및 검증
    private static final String AUTHORITIES_KEY = "auth";
    private static final String TOKEN_ID_KEY = "tokenId";
    private static final String USERNAME_KEY = "username";

    private final Key hashKey;
    private final long accessTokenValidationInMilliseconds;
    private final AccessTokenBlackList accessTokenBlackList;

    public TokenProvider(String secrete, long accessTokenValidationInSeconds, AccessTokenBlackList accessTokenBlackList) {
        byte[] keyBytes = Decoders.BASE64.decode(secrete);
        this.hashKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenValidationInMilliseconds = accessTokenValidationInSeconds * 1000; //초단위로 넘겨줘야하기 때문에 => 밀리초 * 1000
        this.accessTokenBlackList = accessTokenBlackList;
    }

    //토큰 생성
    public TokenInfo createToken(Member member) {
        long currentTime = (new Date()).getTime();
        Date accessTokenExpireTime = new Date(currentTime + this.accessTokenValidationInMilliseconds);
        //토큰 아이디 발급
        String tokenId = UUID.randomUUID().toString();

        //Access 토큰
        String accessToken = Jwts.builder()
                .setSubject(member.getEmail())
                .claim(AUTHORITIES_KEY, member.getRole()) //payload에 정보(claim) 추가
                .claim(USERNAME_KEY, member.getUsername())
                .claim(TOKEN_ID_KEY, tokenId)
                .signWith(hashKey, SignatureAlgorithm.HS512)
                .setExpiration(accessTokenExpireTime)
                .compact();

        //생성한 토큰을 TokenInfo dto에 담아 넘겨줌
        return TokenInfo.builder()
                .ownerEmail(member.getEmail())
                .tokenId(tokenId)
                .accessToken(accessToken)
                .accessTokenExpireTime(accessTokenExpireTime)
                .build();
    }

    //토큰 검증
    public TokenValidationResult validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(hashKey).build().parseClaimsJws(token).getBody();
            return new TokenValidationResult(TokenStatus.TOKEN_VALID, TokenType.ACCESS,
                    claims.get(TOKEN_ID_KEY, String.class),
                    claims);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰");
            return getExpiredTokenValidationResult(e);
        } catch (SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명");
            return new TokenValidationResult(TokenStatus.TOKEN_WRONG_SIGNATURE, null, null, null);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 서명");
            return new TokenValidationResult(TokenStatus.TOKEN_HASH_NOT_SUPPORTED, null, null, null);
        } catch (IllegalArgumentException e) {
            log.info("잘못된 JWT 토큰");
            return new TokenValidationResult(TokenStatus.TOKEN_WRONG_SIGNATURE, null, null, null);
        }
    }

    private TokenValidationResult getExpiredTokenValidationResult(ExpiredJwtException e) {
        Claims claims = e.getClaims();
        return new TokenValidationResult(TokenStatus.TOKEN_EXPIRED, TokenType.ACCESS,
                claims.get(TOKEN_ID_KEY, String.class), null);
    }


    public Authentication getAuthentication(String token, Claims claims) {
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .toList();

        UserPrinciple principle = new UserPrinciple(claims.getSubject(), claims.get(USERNAME_KEY, String.class), authorities);

        return new UsernamePasswordAuthenticationToken(principle, token, authorities);
    }

    public boolean isAccessTokenBlackList(String accessToken) {
        if(accessTokenBlackList.isTokenBlackList(accessToken)) {
            log.info("BlackListed Access Token");
            return true;
        }

        return false;
    }

}
