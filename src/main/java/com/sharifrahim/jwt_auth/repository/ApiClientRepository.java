package com.sharifrahim.jwt_auth.repository;

import com.sharifrahim.jwt_auth.entity.ApiClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ApiClientRepository extends JpaRepository<ApiClient, Long> {
}
