package com.sharifrahim.jwt_auth.service;

import java.time.Instant;
import java.util.Map;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

import com.sharifrahim.jwt_auth.model.Token;
import com.sharifrahim.jwt_auth.util.JWTUtil;

@Component
@RequiredArgsConstructor
public class RefreshToken implements TokenGenerator {
    private final JWTUtil jwtUtil;
    private final long expirationSeconds = 3600; // 1 hour

    @Override
    public Token generate(String subject) {
        Instant expiry = Instant.now().plusSeconds(expirationSeconds);
        String token = jwtUtil.sign(subject, expiry, Map.of("type", "refresh"));
        return new Token(token, expiry);
    }
}
