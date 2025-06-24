package com.sharifrahim.jwt_auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.extern.slf4j.Slf4j;

/**
 * Simple controller exposing secured and public endpoints for testing.
 *
 * Author: sharif rahim
 * <a href="https://github.com/sharifrahim">https://github.com/sharifrahim</a>
 */
@RestController
@Slf4j
public class TestController {

    @GetMapping("/secure/test")
    public String test(Authentication authentication) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        log.debug("Secure endpoint accessed by {}", username);
        return "user " + username + " successfully reached endpoint";
    }

    @GetMapping("/test")
    public String publicTest() {
        log.debug("Public test endpoint called");
        return "public test endpoint";
    }
}
