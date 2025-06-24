package com.sharifrahim.jwt_auth;

import com.sharifrahim.jwt_auth.util.EncryptionUtil;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class EncryptionUtilTests {

    @Autowired
    private EncryptionUtil encryptionUtil;

    @Test
    void encryptAndDecrypt() {
        String original = "hello";
        String encrypted = encryptionUtil.encrypt(original);
        String decrypted = encryptionUtil.decrypt(encrypted);
        assertEquals(original, decrypted);
    }

    @Test
    void generateKeyPair() {
        KeyPair keyPair = encryptionUtil.generateKeyPair();
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }
}
