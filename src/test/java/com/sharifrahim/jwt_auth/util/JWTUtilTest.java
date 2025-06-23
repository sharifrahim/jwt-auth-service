package com.sharifrahim.jwt_auth.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Claims;

class JWTUtilTest {
    JWTUtil util = new JWTUtil();

    @Test
    void signAndValidate() {
        String token = util.sign("user", Instant.now().plusSeconds(60), Map.of("type", "access"));
        Claims claims = util.validate(token);
        assertThat(claims.getSubject()).isEqualTo("user");
    }
}
