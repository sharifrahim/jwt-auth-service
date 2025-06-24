package com.sharifrahim.jwt_auth.service.impl;

import com.sharifrahim.jwt_auth.entity.ApiClient;
import com.sharifrahim.jwt_auth.repository.ApiClientRepository;
import com.sharifrahim.jwt_auth.service.ApiClientService;
import com.sharifrahim.jwt_auth.util.EncryptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Service for CRUD operations on {@link ApiClient} entities.
 *
 * Author: sharif rahim
 * <a href="https://github.com/sharifrahim">https://github.com/sharifrahim</a>
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class ApiClientServiceImpl implements ApiClientService {

    private final ApiClientRepository repository;
    private final EncryptionUtil encryptionUtil;

    @Override
    public ApiClient save(ApiClient client) {
        log.debug("Saving ApiClient with clientId={}", client.getClientId());
        client.setClientSecretEnc(encryptionUtil.encrypt(client.getClientSecretEnc()));
        client.setPrivateKeyEnc(encryptionUtil.encrypt(client.getPrivateKeyEnc()));
        return repository.save(client);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ApiClient> findById(Long id) {
        log.debug("Finding ApiClient by id={}", id);
        return repository.findById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ApiClient> findByClientId(String clientId) {
        log.debug("Finding ApiClient by clientId={}", clientId);
        return repository.findByClientId(clientId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ApiClient> findAll() {
        log.debug("Retrieving all ApiClients");
        return repository.findAll();
    }
}
