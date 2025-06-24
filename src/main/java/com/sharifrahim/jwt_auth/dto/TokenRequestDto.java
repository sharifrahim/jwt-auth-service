package com.sharifrahim.jwt_auth.dto;

import lombok.Data;

/**
 * Request body for obtaining a new JWT token.
 */
@Data
public class TokenRequestDto {
    private String clientId;
    private String clientSecret;
}
