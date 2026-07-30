package org.icpbrasil.signer.providers.birdid;

import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BirdIdApiClientTest {

    @Test
    void parsesSignatureResponse() {
        FakeHttpClient http = new FakeHttpClient("""
                {
                  "certificate_alias": "CERT-TEST:123",
                  "signatures": [{
                    "id": "1",
                    "raw_signature": "%s"
                  }]
                }
                """.formatted(EncodingUtils.toBase64(new byte[]{9, 8, 7})));

        BirdIdApiClient client = new BirdIdApiClient(Environment.HOMOLOGATION, http);
        byte[] signature = client.signHash("token", "CERT-TEST:123", new byte[32], DigestAlgorithm.SHA256);

        assertArrayEquals(new byte[]{9, 8, 7}, signature);
        assertEquals(BirdIdEndpoints.signatureUrl(Environment.HOMOLOGATION), http.lastUrl);
    }

    @Test
    void parsesCertificateDiscovery() throws Exception {
        var credentials = org.icpbrasil.signer.core.cms.TestCertificateFactory.generateRsa2048();
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(credentials.certificate().getEncoded())
                + "\n-----END CERTIFICATE-----";

        FakeHttpClient http = new FakeHttpClient("""
                {
                  "status": "S",
                  "certificates": [{
                    "alias": "CERT-TEST:123",
                    "certificate": "%s"
                  }]
                }
                """.formatted(pem.replace("\n", "\\n")));

        BirdIdApiClient client = new BirdIdApiClient(Environment.HOMOLOGATION, http);
        var certificates = client.discoverCertificates("token");

        assertEquals(1, certificates.size());
        assertEquals("CERT-TEST:123", certificates.get(0).alias());
    }

    @Test
    void rejectsControlCharactersInAlias() {
        assertThrows(IllegalArgumentException.class,
                () -> BirdIdApiClient.validateCertificateAlias("bad\nalias"));
    }

    private static final class FakeHttpClient implements org.icpbrasil.signer.providers.http.HttpClientFacade {

        private final String responseBody;
        private String lastUrl;

        FakeHttpClient(String responseBody) {
            this.responseBody = responseBody;
        }

        @Override
        public String get(String url, java.util.Map<String, String> headers) {
            lastUrl = url;
            return responseBody;
        }

        @Override
        public String postJson(String url, java.util.Map<String, String> headers, String jsonBody) {
            lastUrl = url;
            return responseBody;
        }
    }
}
