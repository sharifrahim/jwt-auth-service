package com.sharifrahim.jwt_auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/secure/test")
    public String test(Authentication authentication) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        return "user " + username + " successfully reached endpoint";
    }

    @GetMapping("/test")
    public String publicTest() {
        return "public test endpoint";
    }
}
