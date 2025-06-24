package com.sharifrahim.jwt_auth;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.sharifrahim.jwt_auth.util.EncryptionUtil;
import com.sharifrahim.jwt_auth.util.JwtUtil;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class JwtUtilTests {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private EncryptionUtil encryptionUtil;

    @Test
    void generateAndValidate() {
        KeyPair pair = encryptionUtil.generateKeyPair();
        String token = jwtUtil.generateToken("bob", Duration.ofMinutes(5), (RSAPrivateKey) pair.getPrivate());
        DecodedJWT decoded = jwtUtil.validateToken(token, (RSAPublicKey) pair.getPublic());
        assertEquals("bob", decoded.getSubject());
    }
}
