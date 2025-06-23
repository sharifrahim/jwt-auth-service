package com.sharifrahim.jwt_auth.service;

import java.time.Instant;

import org.springframework.stereotype.Service;

import com.sharifrahim.jwt_auth.config.AuthProperties;
import com.sharifrahim.jwt_auth.model.Token;
import com.sharifrahim.jwt_auth.service.AccessToken;
import com.sharifrahim.jwt_auth.service.RefreshToken;
import com.sharifrahim.jwt_auth.util.JWTUtil;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final AccessToken accessTokenGenerator;
    private final RefreshToken refreshTokenGenerator;
    private final JWTUtil jwtUtil;
    private final BlacklistService blacklistService;
    private final AuthProperties authProperties;

    public TokenPair createTokens(String clientId, String clientSecret) {
        authenticate(clientId, clientSecret);
        Token access = accessTokenGenerator.generate(clientId);
        Token refresh = refreshTokenGenerator.generate(clientId);
        return new TokenPair(access, refresh);
    }

    public Claims validateAccessToken(String token) {
        if (blacklistService.isBlacklisted(token)) {
            throw new JwtException("Token blacklisted");
        }
        Claims claims = jwtUtil.validate(token);
        if (!"access".equals(claims.get("type"))) {
            throw new JwtException("Invalid access token");
        }
        return claims;
    }

    public TokenPair refreshTokens(String refreshToken) {
        if (blacklistService.isBlacklisted(refreshToken)) {
            throw new JwtException("Token blacklisted");
        }
        Claims claims = jwtUtil.validate(refreshToken);
        if (!"refresh".equals(claims.get("type"))) {
            throw new JwtException("Not a refresh token");
        }
        String subject = claims.getSubject();
        blacklistService.blacklist(refreshToken);
        Token newAccess = accessTokenGenerator.generate(subject);
        Token newRefresh = refreshTokenGenerator.generate(subject);
        return new TokenPair(newAccess, newRefresh);
    }

    private void authenticate(String clientId, String clientSecret) {
        if (!authProperties.getClientId().equals(clientId) || !authProperties.getClientSecret().equals(clientSecret)) {
            throw new JwtException("Invalid client credentials");
        }
    }

    public record TokenPair(Token accessToken, Token refreshToken) {}
}
