package com.sharifrahim.jwt_auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sharifrahim.jwt_auth.model.BlacklistedToken;
import com.sharifrahim.jwt_auth.repository.BlacklistedTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BlacklistService {
    private final BlacklistedTokenRepository repository;

    public boolean isBlacklisted(String token) {
        return repository.existsByTokenHash(hash(token));
    }

    @Transactional
    public void blacklist(String token) {
        if (!isBlacklisted(token)) {
            repository.save(new BlacklistedToken(null, hash(token)));
        }
    }

    private String hash(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
