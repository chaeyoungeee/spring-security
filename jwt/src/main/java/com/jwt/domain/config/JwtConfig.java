package com.jwt.domain.config;

import com.jwt.domain.login.jwt.JwtAuthenticationEntryPoint;
import com.jwt.domain.login.jwt.JwtAccessDeniedHandler;
import com.jwt.domain.login.jwt.JwtProperties;
import com.jwt.domain.login.jwt.blacklist.AccessTokenBlackList;
import com.jwt.domain.login.jwt.token.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {
    private final AccessTokenBlackList accessTokenBlackList;
    @Bean
    public TokenProvider tokenProvider(JwtProperties jwtProperties) {
        return new TokenProvider(jwtProperties.getSecret(), jwtProperties.getAccessTokenValidityInSeconds(), accessTokenBlackList);
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    public JwtAccessDeniedHandler jwtAccessDeniedHandler() {
        return new JwtAccessDeniedHandler();
    }
}
