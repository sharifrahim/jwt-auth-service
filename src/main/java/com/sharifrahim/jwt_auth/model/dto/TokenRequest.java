package com.sharifrahim.jwt_auth.model.dto;

import lombok.Data;

@Data
public class TokenRequest {
    private String clientId;
    private String clientSecret;
}
