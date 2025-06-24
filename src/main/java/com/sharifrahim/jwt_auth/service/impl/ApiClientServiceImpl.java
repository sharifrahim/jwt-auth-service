package com.sharifrahim.jwt_auth.service.impl;

import com.sharifrahim.jwt_auth.entity.ApiClient;
import com.sharifrahim.jwt_auth.repository.ApiClientRepository;
import com.sharifrahim.jwt_auth.service.ApiClientService;
import com.sharifrahim.jwt_auth.util.EncryptionUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class ApiClientServiceImpl implements ApiClientService {

    private final ApiClientRepository repository;
    private final EncryptionUtil encryptionUtil;

    @Override
    public ApiClient save(ApiClient client) {
        client.setClientSecretEnc(encryptionUtil.encrypt(client.getClientSecretEnc()));
        client.setPrivateKeyEnc(encryptionUtil.encrypt(client.getPrivateKeyEnc()));
        return repository.save(client);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ApiClient> findById(Long id) {
        return repository.findById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ApiClient> findAll() {
        return repository.findAll();
    }
}
