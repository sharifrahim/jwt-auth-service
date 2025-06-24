package com.sharifrahim.jwt_auth.service;

import com.sharifrahim.jwt_auth.dto.TokenRequestDto;
import com.sharifrahim.jwt_auth.dto.TokenResponseDto;

import java.util.Optional;

public interface TokenService {
    Optional<TokenResponseDto> createToken(TokenRequestDto request);

    Optional<TokenResponseDto> refreshToken(String refreshToken);

    void validateToken(String token);
}
