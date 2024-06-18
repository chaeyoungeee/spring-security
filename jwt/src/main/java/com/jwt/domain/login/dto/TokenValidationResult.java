package com.jwt.domain.login.dto;

import com.jwt.domain.login.jwt.token.TokenStatus;
import com.jwt.domain.login.jwt.token.TokenType;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@AllArgsConstructor
public class TokenValidationResult { //토큰 검증 결과를 가지고 있는 클래스
    private TokenStatus tokenStatus;
    private TokenType tokenType;
    private String tokenId;
    private Claims claims;

    public String getEmail() {
        if (claims == null) {
            throw new IllegalStateException("Claim value is null.");
        }
        return claims.getSubject();
    }

    public boolean isValid() {
        return TokenStatus.TOKEN_VALID == this.tokenStatus;
    }

}
