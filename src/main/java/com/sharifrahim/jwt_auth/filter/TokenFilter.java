package com.sharifrahim.jwt_auth.filter;

import com.sharifrahim.jwt_auth.service.TokenService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Servlet filter that validates JWT tokens on secured endpoints.
 *
 * Author: sharif rahim
 * <a href="https://github.com/sharifrahim">https://github.com/sharifrahim</a>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TokenFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getServletPath();
        if (path.startsWith("/secured")) {
            String header = request.getHeader("Authorization");
            if (header == null || !header.startsWith("Bearer ")) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing token");
                return;
            }
            String token = header.substring(7);
            try {
                log.debug("Validating token for request to {}", path);
                tokenService.validateToken(token);
                DecodedJWT decoded = JWT.decode(token);
                String username = decoded.getClaim("username").asString();
                Authentication auth = new UsernamePasswordAuthenticationToken(username, null, java.util.Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                log.warn("Invalid token: {}", e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
