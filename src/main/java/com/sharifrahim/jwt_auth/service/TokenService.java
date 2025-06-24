package com.sharifrahim.jwt_auth.service;

import com.sharifrahim.jwt_auth.dto.TokenRequestDto;
import com.sharifrahim.jwt_auth.dto.TokenResponseDto;

import java.util.Optional;

/**
 * Service abstraction for issuing and validating JWT tokens.
 *
 * Author: sharif rahim
 * <a href="https://github.com/sharifrahim">https://github.com/sharifrahim</a>
 */
public interface TokenService {
    /**
     * Create a pair of access and refresh tokens for the specified client.
     */
    Optional<TokenResponseDto> createToken(TokenRequestDto request);

    /**
     * Refresh an access token using the provided refresh token.
     */
    Optional<TokenResponseDto> refreshToken(String refreshToken);

    /**
     * Validate the authenticity and expiration of a JWT token.
     */
    void validateToken(String token);
}
