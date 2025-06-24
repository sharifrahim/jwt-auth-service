package com.sharifrahim.jwt_auth.dto;

import lombok.Data;

@Data
public class RefreshTokenRequestDto {
    private String refreshToken;
}
