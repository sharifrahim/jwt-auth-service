package com.sharifrahim.jwt_auth.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.sharifrahim.jwt_auth.config.AuthProperties;

import io.jsonwebtoken.Claims;

@SpringBootTest
class TokenServiceTest {

    @Autowired
    TokenService tokenService;
    @Autowired
    AuthProperties authProperties;

    @Test
    void createAndValidate() {
        TokenService.TokenPair pair = tokenService.createTokens(authProperties.getClientId(), authProperties.getClientSecret());
        Claims claims = tokenService.validateAccessToken(pair.accessToken().getValue());
        assertThat(claims.getSubject()).isEqualTo(authProperties.getClientId());
    }

    @Test
    void refresh() {
        TokenService.TokenPair pair = tokenService.createTokens(authProperties.getClientId(), authProperties.getClientSecret());
        TokenService.TokenPair refreshed = tokenService.refreshTokens(pair.refreshToken().getValue());
        assertThat(tokenService.validateAccessToken(refreshed.accessToken().getValue()).getSubject())
                .isEqualTo(authProperties.getClientId());
    }
}
