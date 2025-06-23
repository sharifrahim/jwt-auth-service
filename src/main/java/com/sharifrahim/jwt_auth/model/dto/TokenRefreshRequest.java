package com.sharifrahim.jwt_auth.model.dto;

import lombok.Data;

@Data
public class TokenRefreshRequest {
    private String refreshToken;
}
