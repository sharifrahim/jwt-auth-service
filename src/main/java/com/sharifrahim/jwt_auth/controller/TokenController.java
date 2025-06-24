package com.sharifrahim.jwt_auth.controller;

import com.sharifrahim.jwt_auth.dto.TokenRequestDto;
import com.sharifrahim.jwt_auth.dto.TokenResponseDto;
import com.sharifrahim.jwt_auth.dto.RefreshTokenRequestDto;
import com.sharifrahim.jwt_auth.dto.ApiResponse;
import com.sharifrahim.jwt_auth.dto.ResponseStatus;
import com.sharifrahim.jwt_auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class TokenController {

    private final TokenService tokenService;

    @PostMapping("/token")
    public ResponseEntity<ApiResponse<TokenResponseDto>> createToken(@RequestBody TokenRequestDto request) {
        return tokenService.createToken(request)
                .map(token -> ResponseEntity.ok(ApiResponse.of(ResponseStatus.SUCCESS, token)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.of(ResponseStatus.UNAUTHORIZED, null)));
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<ApiResponse<TokenResponseDto>> refreshToken(@RequestBody RefreshTokenRequestDto request) {
        return tokenService.refreshToken(request.getRefreshToken())
                .map(token -> ResponseEntity.ok(ApiResponse.of(ResponseStatus.SUCCESS, token)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.of(ResponseStatus.UNAUTHORIZED, null)));
    }
}
