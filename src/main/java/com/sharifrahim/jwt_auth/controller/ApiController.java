package com.sharifrahim.jwt_auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sharifrahim.jwt_auth.service.TokenService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {
    private final TokenService tokenService;

    @GetMapping("/data")
    public ResponseEntity<String> protectedEndpoint(@RequestHeader("Authorization") String auth) {
        String token = auth.replace("Bearer ", "");
        tokenService.validateAccessToken(token);
        return ResponseEntity.ok("secured data");
    }
}
