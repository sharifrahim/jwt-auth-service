package com.sharifrahim.jwt_auth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Date;
import java.util.Map;

/**
 * Helper methods for generating and validating JWT tokens.
 *
 * Author: sharif rahim
 * <a href="https://github.com/sharifrahim">https://github.com/sharifrahim</a>
 */
@Component
@Slf4j
public class JwtUtil {

    public String generateToken(String subject, Duration validity, RSAPrivateKey privateKey) {
        return generateToken(subject, validity, privateKey, null);
    }

    public String generateToken(String subject, Duration validity, RSAPrivateKey privateKey, Map<String, String> claims) {
        Algorithm algorithm = Algorithm.RSA256(null, privateKey);
        long nowMillis = System.currentTimeMillis();
        var builder = JWT.create()
                .withSubject(subject)
                .withIssuedAt(new Date(nowMillis))
                .withExpiresAt(new Date(nowMillis + validity.toMillis()));
        if (claims != null) {
            claims.forEach(builder::withClaim);
        }
        String token = builder.sign(algorithm);
        log.debug("Generated token for subject {}", subject);
        return token;
    }

    public DecodedJWT validateToken(String token, RSAPublicKey publicKey) {
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decoded = verifier.verify(token);
        log.debug("Validated token for subject {}", decoded.getSubject());
        return decoded;
    }
}
