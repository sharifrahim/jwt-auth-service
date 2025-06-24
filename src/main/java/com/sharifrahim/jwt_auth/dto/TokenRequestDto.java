package com.sharifrahim.jwt_auth.dto;

import lombok.Data;

@Data
public class TokenRequestDto {
    private String clientId;
    private String clientSecret;
}
