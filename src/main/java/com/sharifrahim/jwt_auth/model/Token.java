package com.sharifrahim.jwt_auth.model;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Token {
    private String value;
    private Instant expiry;
}
