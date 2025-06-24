package com.sharifrahim.jwt_auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Wrapper for API responses used by the service.
 *
 * Author: sharif rahim
 * <a href="https://github.com/sharifrahim">https://github.com/sharifrahim</a>
 */
@Data
@AllArgsConstructor
public class ApiResponse<T> {
    private int statusCode;
    private String message;
    private T data;

    public static <T> ApiResponse<T> of(ResponseStatus status, T data) {
        return new ApiResponse<>(status.getStatus().value(), status.getMessage(), data);
    }
}
