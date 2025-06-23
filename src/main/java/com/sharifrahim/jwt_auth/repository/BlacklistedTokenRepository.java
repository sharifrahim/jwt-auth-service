package com.sharifrahim.jwt_auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sharifrahim.jwt_auth.model.BlacklistedToken;

import java.util.Optional;

public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {
    Optional<BlacklistedToken> findByTokenHash(String tokenHash);
    boolean existsByTokenHash(String tokenHash);
}
