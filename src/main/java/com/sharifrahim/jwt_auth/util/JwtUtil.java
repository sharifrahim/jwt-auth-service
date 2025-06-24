package com.sharifrahim.jwt_auth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Date;

@Component
public class JwtUtil {

    public String generateToken(String subject, Duration validity, RSAPrivateKey privateKey) {
        Algorithm algorithm = Algorithm.RSA256(null, privateKey);
        long nowMillis = System.currentTimeMillis();
        return JWT.create()
                .withSubject(subject)
                .withIssuedAt(new Date(nowMillis))
                .withExpiresAt(new Date(nowMillis + validity.toMillis()))
                .sign(algorithm);
    }

    public DecodedJWT validateToken(String token, RSAPublicKey publicKey) {
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }
}
