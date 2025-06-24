package com.sharifrahim.jwt_auth.service;

import com.sharifrahim.jwt_auth.entity.ApiClient;

import java.util.List;
import java.util.Optional;

public interface ApiClientService {

    ApiClient save(ApiClient client);

    Optional<ApiClient> findById(Long id);

    List<ApiClient> findAll();
}
