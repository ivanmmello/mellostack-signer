package org.icpbrasil.signer.providers.iti;

import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.iti.HashEncoding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ItiCloudPscApiClientTest {

    private static final ItiCloudPscEndpoints ENDPOINTS =
            new ItiCloudPscEndpoints("https://psc.test.local");

    @Mock
    private HttpClientFacade httpClient;

    @Test
    void signsHashWithBase64Encoding() throws Exception {
        when(httpClient.postJson(eq(ENDPOINTS.signatureUrl()), anyMap(), anyString()))
                .thenReturn("""
                        {
                          "signatures": [{
                            "id": "1",
                            "raw_signature": "%s"
                          }]
                        }
                        """.formatted(EncodingUtils.toBase64(new byte[]{1, 2, 3})));

        ItiCloudPscApiClient client = new ItiCloudPscApiClient(
                ENDPOINTS,
                httpClient,
                HashEncoding.BASE64,
                "TestPSC"
        );

        byte[] signature = client.signHash("token", "alias-1", new byte[32], DigestAlgorithm.SHA256);

        assertArrayEquals(new byte[]{1, 2, 3}, signature);
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(httpClient).postJson(eq(ENDPOINTS.signatureUrl()), anyMap(), bodyCaptor.capture());
        assertTrue(bodyCaptor.getValue().contains(EncodingUtils.toBase64(new byte[32])));
    }

    @Test
    void signsHashWithHexEncoding() throws Exception {
        byte[] hash = new byte[32];
        hash[0] = 0x0A;

        when(httpClient.postJson(eq(ENDPOINTS.signatureUrl()), anyMap(), anyString()))
                .thenReturn("""
                        {
                          "status": "S",
                          "raw_signature": "%s"
                        }
                        """.formatted(EncodingUtils.toBase64(new byte[]{4, 5, 6})));

        ItiCloudPscApiClient client = new ItiCloudPscApiClient(
                ENDPOINTS,
                httpClient,
                HashEncoding.HEX,
                "TestPSC"
        );

        byte[] signature = client.signHash("token", "alias-1", hash, DigestAlgorithm.SHA256);

        assertArrayEquals(new byte[]{4, 5, 6}, signature);
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(httpClient).postJson(eq(ENDPOINTS.signatureUrl()), anyMap(), bodyCaptor.capture());
        assertTrue(bodyCaptor.getValue().contains(EncodingUtils.toHex(hash)));
    }

    @Test
    void discoversCertificates() throws Exception {
        var credentials = TestCertificateFactory.generateRsa2048();
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(credentials.certificate().getEncoded())
                + "\n-----END CERTIFICATE-----";

        when(httpClient.get(eq(ENDPOINTS.certificateDiscoveryUrl()), anyMap()))
                .thenReturn("""
                        {
                          "status": "S",
                          "certificates": [{
                            "alias": "CERT-1",
                            "certificate": "%s"
                          }]
                        }
                        """.formatted(pem.replace("\n", "\\n")));

        ItiCloudPscApiClient client = new ItiCloudPscApiClient(
                ENDPOINTS,
                httpClient,
                HashEncoding.BASE64,
                "TestPSC"
        );

        var certificates = client.discoverCertificates("token");

        assertEquals(1, certificates.size());
        assertEquals("CERT-1", certificates.get(0).alias());
        verify(httpClient).get(eq(ENDPOINTS.certificateDiscoveryUrl()), anyMap());
    }
}
