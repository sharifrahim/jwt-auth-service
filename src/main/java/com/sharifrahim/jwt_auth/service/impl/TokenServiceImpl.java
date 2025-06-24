package com.sharifrahim.jwt_auth.service.impl;

import com.sharifrahim.jwt_auth.dto.TokenRequestDto;
import com.sharifrahim.jwt_auth.dto.TokenResponseDto;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sharifrahim.jwt_auth.entity.ApiClient;
import com.sharifrahim.jwt_auth.service.ApiClientService;
import com.sharifrahim.jwt_auth.service.TokenService;
import com.sharifrahim.jwt_auth.util.EncryptionUtil;
import com.sharifrahim.jwt_auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final ApiClientService apiClientService;
    private final EncryptionUtil encryptionUtil;
    private final JwtUtil jwtUtil;

    @Override
    @Transactional
    public Optional<TokenResponseDto> createToken(TokenRequestDto request) {
        return apiClientService.findByClientId(request.getClientId())
                .filter(c -> clientSecretMatches(c, request.getClientSecret()))
                .map(c -> generateTokensForClient(c, request.getClientSecret()));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<TokenResponseDto> refreshToken(String refreshToken) {
        try {
            DecodedJWT decoded = JWT.decode(refreshToken);
            String clientId = decoded.getSubject();
            return apiClientService.findByClientId(clientId)
                    .map(client -> {
                        String secret = encryptionUtil.decrypt(client.getClientSecretEnc());
                        RSAPrivateKey privateKey = ensurePrivateKey(client, secret);
                        RSAPublicKey publicKey = toPublicKey(privateKey);
                        jwtUtil.validateToken(refreshToken, publicKey);
                        return generateTokensForClient(client, secret);
                    });
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    @Transactional(readOnly = true)
    public void validateToken(String token) {
        DecodedJWT decoded = JWT.decode(token);
        String clientId = decoded.getSubject();
        ApiClient client = apiClientService.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid token"));
        String secret = encryptionUtil.decrypt(client.getClientSecretEnc());
        RSAPrivateKey privateKey = ensurePrivateKey(client, secret);
        RSAPublicKey publicKey = toPublicKey(privateKey);
        jwtUtil.validateToken(token, publicKey);
    }

    private boolean clientSecretMatches(ApiClient client, String clientSecret) {
        String decrypted = encryptionUtil.decrypt(client.getClientSecretEnc());
        return decrypted.equals(clientSecret);
    }

    private TokenResponseDto generateTokensForClient(ApiClient client, String clientSecret) {
        RSAPrivateKey key = ensurePrivateKey(client, clientSecret);
        Map<String, String> claims = new HashMap<>();
        claims.put("username", client.getUsername());
        claims.put("fullName", client.getFullName());
        claims.put("companyName", client.getCompanyName());
        claims.put("registrationNo", client.getRegistrationNo());
        String accessToken = jwtUtil.generateToken(client.getClientId(), Duration.ofHours(1), key, claims);
        String refreshToken = jwtUtil.generateToken(client.getClientId(), Duration.ofDays(7), key);
        return new TokenResponseDto(accessToken, refreshToken);
    }

    private RSAPrivateKey ensurePrivateKey(ApiClient client, String clientSecret) {
        String privateKeyPlain = encryptionUtil.decrypt(client.getPrivateKeyEnc());
        if (privateKeyPlain == null || privateKeyPlain.isBlank()) {
            KeyPair pair = encryptionUtil.generateKeyPair();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) pair.getPrivate();
            privateKeyPlain = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());
            client.setPrivateKeyEnc(privateKeyPlain);
            client.setClientSecretEnc(clientSecret);
            apiClientService.save(client);
        }
        return toPrivateKey(privateKeyPlain);
    }

    private RSAPrivateKey toPrivateKey(String key) {
        try {
            byte[] bytes = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) factory.generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid private key", e);
        }
    }

    private RSAPublicKey toPublicKey(RSAPrivateKey privateKey) {
        try {
            RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec spec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) factory.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid private key", e);
        }
    }
}
