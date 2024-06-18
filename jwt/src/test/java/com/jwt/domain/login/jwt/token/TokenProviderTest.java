package com.jwt.domain.login.jwt.token;

import com.jwt.domain.login.dto.TokenInfo;
import com.jwt.domain.login.dto.TokenValidationResult;
import com.jwt.domain.member.Member;
import com.jwt.domain.member.Role;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class TokenProviderTest {
    private final String secrete = "dGhpcyBpcyBteSBoaWRkZW4gand0IHNlY3JldGUga2V5LCB3aGF0IGlzIHlvdXIgand0IHNlY3JldGUga2V5Pw==";
    //토큰 만료 시간 3초
    private final Long accessTokenValidTimeInSeconds = 3L;
    private final TokenProvider tokenProvider = new TokenProvider(secrete, accessTokenValidTimeInSeconds);

    @Test
    void createToken() {
        Member member = getMember();
        TokenInfo token = tokenProvider.createToken(member);
        log.info("access token=>{}", token.getAccessToken());
    }

    @Test
    void validateTokenValid() {
        Member member = getMember();
        TokenInfo token = tokenProvider.createToken(member);
        String accessToken = token.getAccessToken();

        TokenValidationResult tokenValidationResult = tokenProvider.validateToken(accessToken);
        Assertions.assertThat(tokenValidationResult.isValid()).isTrue();
    }

    @Test
    void validateTokenNotValid() throws InterruptedException {
        Member member = getMember();
        TokenInfo token = tokenProvider.createToken(member);
        String accessToken = token.getAccessToken();

        Thread.sleep(4000);
        TokenValidationResult tokenValidationResult = tokenProvider.validateToken(accessToken);
        Assertions.assertThat(tokenValidationResult.isValid()).isFalse();
    }

    private Member getMember() {
        return Member.builder()
                .email("test@test.ac.kr")
                .password("1234")
                .username("test_user")
                .role(Role.ROLE_USER)
                .build();
    }

}