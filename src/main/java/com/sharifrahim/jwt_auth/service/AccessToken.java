package com.sharifrahim.jwt_auth.service;

import java.time.Instant;
import java.util.Map;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

import com.sharifrahim.jwt_auth.model.Token;
import com.sharifrahim.jwt_auth.util.JWTUtil;

@Component
@RequiredArgsConstructor
public class AccessToken implements TokenGenerator {
    private final JWTUtil jwtUtil;
    private final long expirationSeconds = 600; // 10 minutes

    @Override
    public Token generate(String subject) {
        Instant expiry = Instant.now().plusSeconds(expirationSeconds);
        String token = jwtUtil.sign(subject, expiry, Map.of("type", "access"));
        return new Token(token, expiry);
    }
}
