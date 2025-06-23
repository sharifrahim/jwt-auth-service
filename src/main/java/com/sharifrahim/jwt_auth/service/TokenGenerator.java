package com.sharifrahim.jwt_auth.service;

import com.sharifrahim.jwt_auth.model.Token;

public interface TokenGenerator {
    Token generate(String subject);
}
