package com.sharifrahim.jwt_auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sharifrahim.jwt_auth.model.dto.TokenRefreshRequest;
import com.sharifrahim.jwt_auth.model.dto.TokenRequest;
import com.sharifrahim.jwt_auth.model.dto.TokenResponse;
import com.sharifrahim.jwt_auth.service.TokenService;
import com.sharifrahim.jwt_auth.service.TokenService.TokenPair;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class TokenController {
    private final TokenService tokenService;

    @PostMapping
    public ResponseEntity<TokenResponse> token(@RequestBody TokenRequest request) {
        TokenPair pair = tokenService.createTokens(request.getClientId(), request.getClientSecret());
        return ResponseEntity.ok(new TokenResponse(pair.accessToken().getValue(), pair.refreshToken().getValue(),
                pair.accessToken().getExpiry().getEpochSecond()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody TokenRefreshRequest request) {
        TokenPair pair = tokenService.refreshTokens(request.getRefreshToken());
        return ResponseEntity.ok(new TokenResponse(pair.accessToken().getValue(), pair.refreshToken().getValue(),
                pair.accessToken().getExpiry().getEpochSecond()));
    }
}
