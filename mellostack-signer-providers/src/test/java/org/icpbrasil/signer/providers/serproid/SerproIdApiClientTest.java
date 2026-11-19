package org.icpbrasil.signer.providers.serproid;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SerproIdApiClientTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void signsSha256HashAsBase64RawWithoutCertificateAlias() throws Exception {
        byte[] hash = new byte[32];
        hash[0] = 4;
        RecordingHttp http = new RecordingHttp("""
                {"signatures":[{"id":"1","raw_signature":"%s"}]}
                """.formatted(EncodingUtils.toBase64(new byte[] {9, 8, 7})));

        SerproIdApiClient client = new SerproIdApiClient(Environment.HOMOLOGATION, http);
        byte[] signature = client.signHash("token", "alias-1", hash, DigestAlgorithm.SHA256);

        assertArrayEquals(new byte[] {9, 8, 7}, signature);
        assertEquals(
                "https://hom.serproid.serpro.gov.br/oauth/v0/oauth/signature",
                http.lastUrl);
        JsonNode body = MAPPER.readTree(http.lastJsonBody);
        assertFalse(body.has("certificate_alias"));
        assertEquals(EncodingUtils.toBase64(hash), body.get("hashes").get(0).get("hash").asText());
        assertEquals("2.16.840.1.101.3.4.2.1", body.get("hashes").get(0).get("hash_algorithm").asText());
        assertEquals("RAW", body.get("hashes").get(0).get("signature_format").asText());
        assertEquals("Bearer token", http.lastHeaders.get("Authorization"));
    }

    @Test
    void rejectsSha384Hash() {
        SerproIdApiClient client = new SerproIdApiClient(Environment.HOMOLOGATION, new RecordingHttp("{}"));

        assertThrows(PscSigningException.class,
                () -> client.signHash("token", "alias", new byte[48], DigestAlgorithm.SHA256));
    }

    @Test
    void rejectsMoreThanFiveHashes() {
        SerproIdApiClient client = new SerproIdApiClient(Environment.PRODUCTION, new RecordingHttp("{}"));

        assertThrows(IllegalArgumentException.class, () -> client.signHashes(
                "token",
                "alias",
                java.util.List.of(new byte[32], new byte[32], new byte[32], new byte[32], new byte[32], new byte[32])));
        assertTrue(SerproIdEndpoints.baseUrl(Environment.PRODUCTION).contains("serproid.serpro.gov.br"));
    }

    private static final class RecordingHttp implements HttpClientFacade {

        private final String response;
        private String lastUrl;
        private String lastJsonBody;
        private Map<String, String> lastHeaders = Map.of();

        private RecordingHttp(String response) {
            this.response = response;
        }

        @Override
        public String get(String url, Map<String, String> headers) {
            return response;
        }

        @Override
        public String postJson(String url, Map<String, String> headers, String jsonBody) {
            lastUrl = url;
            lastHeaders = headers;
            lastJsonBody = jsonBody;
            return response;
        }
    }
}
