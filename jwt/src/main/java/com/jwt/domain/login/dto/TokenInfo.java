package com.jwt.domain.login.dto;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;

import java.util.Date;

@Data
//accessToken이 너무 길기때문에 출력시 로그가 너무 길어져 accessToken은 제외
@ToString(exclude = {"accessToken"})
public class TokenInfo {
    private String  accessToken;
    private Date accessTokenExpireTime;
    private String ownerEmail;
    private String tokenId;

    @Builder
    public TokenInfo(String accessToken, Date accessTokenExpireTime, String ownerEmail, String tokenId) {
        this.accessToken = accessToken;
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.ownerEmail = ownerEmail;
        this.tokenId = tokenId;
    }
}
