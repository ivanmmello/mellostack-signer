package org.icpbrasil.signer.providers.http;

import org.junit.jupiter.api.Test;
import org.icpbrasil.signer.providers.exception.PscHttpException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureHttpClientTest {

    @Test
    void rejectsNonHttpsUrls() {
        SecureHttpClient client = new SecureHttpClient(HttpClientConfig.defaults());
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> client.get("http://api.example.com/test", java.util.Map.of()));
        assertTrue(error.getMessage().contains("Only HTTPS"));
    }

    @Test
    void allowsLocalhostHttpOnlyInTestMode() {
        HttpClientConfig config = HttpClientConfig.builder()
                .allowInsecureHttpForTesting(true)
                .build();
        assertThrows(PscHttpException.class, () ->
                new SecureHttpClient(config).get("http://localhost:9999/unreachable", java.util.Map.of()));
    }
}
