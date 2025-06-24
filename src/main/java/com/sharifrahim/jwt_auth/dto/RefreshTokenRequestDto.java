package com.sharifrahim.jwt_auth.dto;

import lombok.Data;

/**
 * Request body containing a refresh token for re-issuing access tokens.
 */
@Data
public class RefreshTokenRequestDto {
    private String refreshToken;
}
