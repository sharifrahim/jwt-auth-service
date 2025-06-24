package com.sharifrahim.jwt_auth.controller;

import com.sharifrahim.jwt_auth.dto.TokenRequestDto;
import com.sharifrahim.jwt_auth.dto.TokenResponseDto;
import com.sharifrahim.jwt_auth.dto.RefreshTokenRequestDto;
import com.sharifrahim.jwt_auth.dto.ApiResponse;
import com.sharifrahim.jwt_auth.dto.ResponseStatus;
import com.sharifrahim.jwt_auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST endpoints for obtaining and refreshing JWT tokens.
 *
 * Author: sharif rahim
 * <a href="https://github.com/sharifrahim">https://github.com/sharifrahim</a>
 */
@RequiredArgsConstructor
@RestController
@Slf4j
public class TokenController {

    private final TokenService tokenService;

    /**
     * Create new JWT access and refresh tokens for the given client credentials.
     */
    @PostMapping("/token")
    public ResponseEntity<ApiResponse<TokenResponseDto>> createToken(@RequestBody TokenRequestDto request) {
        log.debug("Token request for clientId={}", request.getClientId());
        return tokenService.createToken(request)
                .map(token -> ResponseEntity.ok(ApiResponse.of(ResponseStatus.SUCCESS, token)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.of(ResponseStatus.UNAUTHORIZED, null)));
    }

    /**
     * Refresh an access token using an existing refresh token.
     */
    @PostMapping("/token/refresh")
    public ResponseEntity<ApiResponse<TokenResponseDto>> refreshToken(@RequestBody RefreshTokenRequestDto request) {
        log.debug("Refresh token request");
        return tokenService.refreshToken(request.getRefreshToken())
                .map(token -> ResponseEntity.ok(ApiResponse.of(ResponseStatus.SUCCESS, token)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.of(ResponseStatus.UNAUTHORIZED, null)));
    }
}
