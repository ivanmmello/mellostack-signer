package org.icpbrasil.signer.providers.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitiveRedactorTest {

    @Test
    void redactsBearerToken() {
        String input = "Authorization failed: Bearer abc123secret456";
        String redacted = SensitiveRedactor.redact(input);
        assertTrue(redacted.contains("Bearer ***"));
        assertFalse(redacted.contains("abc123secret456"));
    }

    @Test
    void redactsClientSecretInJson() {
        String input = "{\"client_secret\":\"super-secret-value\"}";
        String redacted = SensitiveRedactor.redact(input);
        assertEquals("{\"client_secret\":\"***\"}", redacted);
    }

    @Test
    void fingerprintIsStableAndDistinct() {
        String first = SensitiveRedactor.fingerprint("token-a");
        String second = SensitiveRedactor.fingerprint("token-b");
        assertEquals(first, SensitiveRedactor.fingerprint("token-a"));
        assertNotEquals(first, second);
    }
}
