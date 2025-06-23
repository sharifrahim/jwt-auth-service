package com.sharifrahim.jwt_auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
    private String clientId;
    private String clientSecret;
    private String secretKey;
}
