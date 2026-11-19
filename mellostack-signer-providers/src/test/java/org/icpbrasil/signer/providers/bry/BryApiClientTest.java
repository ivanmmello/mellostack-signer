package org.icpbrasil.signer.providers.bry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BryApiClientTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private RecordingHttp http;
    private BryApiClient client;
    private String certificateBase64;

    @BeforeEach
    void setUp() throws Exception {
        certificateBase64 = Base64.getEncoder().encodeToString(
                TestCertificateFactory.generateRsa2048().certificate().getEncoded());
        http = new RecordingHttp(certificateBase64);
        client = new BryApiClient(
                Environment.HOMOLOGATION,
                "app id",
                "secret+value",
                "https://integra.hom.bry.com.br/api/service",
                http);
    }

    @Test
    void createLinkUsesApplicationJwtAndReturnsSignerCredential() throws Exception {
        BryAuthorizationLink link = client.createAuthorizationLink(BryAuthorizationRequest.builder()
                .psc(BryPsc.BIRD_ID)
                .redirectUri("https://app.example/callback")
                .state("session-1")
                .scope(BrySignatureScope.SINGLE_SIGNATURE)
                .build());

        assertEquals("signer-token", link.signerToken());
        assertEquals("https://psc.example/authorize", link.authorizationUrl());
        assertEquals(BryEndpoints.pscLinkUrl(Environment.HOMOLOGATION), http.jsonPosts.get(0).url());
        assertEquals("Bearer app-jwt", http.jsonPosts.get(0).headers().get("Authorization"));
        assertTrue(http.formBody.contains("grant_type=client_credentials"));
        assertTrue(http.formBody.contains("client_id=app+id"));
        assertTrue(http.formBody.contains("client_secret=secret%2Bvalue"));
        JsonNode body = MAPPER.readTree(http.jsonPosts.get(0).body());
        assertEquals("BirdID", body.get("pscName").asText());
        assertEquals("session-1", body.get("state").asText());
    }

    @Test
    void signCmsSendsSha256HashAndKmsTypePsc() throws Exception {
        byte[] hash = new byte[32];
        hash[0] = 4;

        List<byte[]> signatures = client.signCmsHashes("signer-token", List.of(hash));

        assertEquals(1, signatures.size());
        assertEquals(9, signatures.get(0)[0]);
        RecordingHttp.Call cmsCall = http.jsonPosts.get(http.jsonPosts.size() - 1);
        assertEquals(BryEndpoints.cmsSignatureUrl(Environment.HOMOLOGATION), cmsCall.url());
        assertEquals("PSC", cmsCall.headers().get("kms_type"));
        JsonNode body = MAPPER.readTree(cmsCall.body());
        assertEquals("HASH", body.get("formatoAssinatura").asText());
        assertEquals("SHA256", body.get("algoritmoHash").asText());
        assertEquals("BASIC", body.get("perfil").asText());
        assertEquals(EncodingUtils.toBase64(hash), body.get("hashes").get(0).asText());
        assertEquals("signer-token", body.get("kms_data").get("token").asText());
        assertEquals(
                "https://integra.hom.bry.com.br/api/service",
                body.get("kms_data").get("url").asText());
    }

    @Test
    void fetchesCertificateWithSignerCredential() throws Exception {
        var certificate = client.fetchCertificate("signer-token");

        assertEquals(certificateBase64, Base64.getEncoder().encodeToString(certificate.getEncoded()));
        assertEquals(BryEndpoints.certificateUrl(Environment.HOMOLOGATION), http.lastGetUrl);
        assertEquals("signer-token", http.lastGetHeaders.get("X-API-KEY"));
        assertEquals("Bearer app-jwt", http.lastGetHeaders.get("Authorization"));
    }

    private static final class RecordingHttp implements HttpClientFacade {

        private final String certificateBase64;
        private final List<Call> jsonPosts = new ArrayList<>();
        private String formBody = "";
        private String lastGetUrl;
        private Map<String, String> lastGetHeaders = Map.of();

        private RecordingHttp(String certificateBase64) {
            this.certificateBase64 = certificateBase64;
        }

        @Override
        public String get(String url, Map<String, String> headers) {
            lastGetUrl = url;
            lastGetHeaders = headers;
            return "{\"content\":\"" + certificateBase64 + "\"}";
        }

        @Override
        public String postJson(String url, Map<String, String> headers, String jsonBody) {
            jsonPosts.add(new Call(url, headers, jsonBody));
            if (url.endsWith("/psc/link")) {
                return "{\"token\":\"signer-token\",\"url\":\"https://psc.example/authorize\"}";
            }
            return "{\"assinaturas\":[\"" + Base64.getEncoder().encodeToString(new byte[] {9}) + "\"]}";
        }

        @Override
        public String postForm(String url, Map<String, String> headers, String formBody) {
            this.formBody = formBody;
            return "{\"access_token\":\"app-jwt\",\"expires_in\":3600,\"token_type\":\"Bearer\"}";
        }

        private record Call(String url, Map<String, String> headers, String body) {
        }
    }
}
