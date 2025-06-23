package com.sharifrahim.jwt_auth.util;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTUtil {
    private final KeyPair keyPair;

    public JWTUtil() {
        this.keyPair = EncryptionUtil.generateKeyPair();
    }

    public String sign(String subject, Instant expiry, Map<String, Object> claims) {
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setExpiration(Date.from(expiry))
                .setIssuedAt(new Date())
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    public Claims validate(String token) {
        return Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }
}
