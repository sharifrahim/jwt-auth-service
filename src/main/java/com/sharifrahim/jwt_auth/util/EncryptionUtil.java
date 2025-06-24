package com.sharifrahim.jwt_auth.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

@Component
public class EncryptionUtil {

    private final SecretKeySpec secretKey;
    private final IvParameterSpec ivParameterSpec;

    public EncryptionUtil(@Value("${encryption.secret-key}") String key,
                          @Value("${encryption.salt}") String salt) {
        try {
            byte[] keyBytes = Arrays.copyOf(MessageDigest.getInstance("SHA-256")
                    .digest(key.getBytes(StandardCharsets.UTF_8)), 16);
            this.secretKey = new SecretKeySpec(keyBytes, "AES");

            byte[] ivBytes = Arrays.copyOf(MessageDigest.getInstance("SHA-256")
                    .digest(salt.getBytes(StandardCharsets.UTF_8)), 16);
            this.ivParameterSpec = new IvParameterSpec(ivBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to initialize EncryptionUtil", e);
        }
    }

    public String encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    public String decrypt(String encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decoded = Base64.getDecoder().decode(encrypted);
            return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to generate RSA key pair", e);
        }
    }
}
