package com.sharifrahim.jwt_auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * DTO returned to clients after successful token generation.
 */
@Data
@AllArgsConstructor
public class TokenResponseDto {
    private String accessToken;
    private String refreshToken;
}
