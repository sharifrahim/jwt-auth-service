package com.sharifrahim.jwt_auth.dto;

import org.springframework.http.HttpStatus;

public enum ResponseStatus {
    SUCCESS(HttpStatus.OK, "Success"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Unauthorized");

    private final HttpStatus status;
    private final String message;

    ResponseStatus(HttpStatus status, String message) {
        this.status = status;
        this.message = message;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }
}
