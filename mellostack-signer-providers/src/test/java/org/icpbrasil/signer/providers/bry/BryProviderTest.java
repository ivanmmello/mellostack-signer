package org.icpbrasil.signer.providers.bry;

import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.security.SecureTokenCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BryProviderTest {

    private RecordingGateway gateway;
    private BryProvider provider;
    private X509Certificate certificate;

    @BeforeEach
    void setUp() throws Exception {
        certificate = TestCertificateFactory.generateRsa2048().certificate();
        gateway = new RecordingGateway(certificate);
        provider = new BryProvider(
                Environment.HOMOLOGATION,
                gateway,
                new SecureTokenCache<>(BryProvider.CERTIFICATE_CACHE_TTL));
    }

    @Test
    void reportsPreparedCmsAndBatchSupport() {
        assertEquals("bry", provider.getProviderId());
        assertTrue(provider.returnsPreparedCms());
        assertTrue(provider.supportsBatchSigning());
    }

    @Test
    void signHashReturnsCmsFromGateway() {
        byte[] hash = new byte[32];
        hash[0] = 7;
        byte[] cms = provider.signHash(hash, "signer-token");

        assertArrayEquals(new byte[] {9, 8, 7}, cms);
        assertEquals(List.of(hash), gateway.signedHashes);
        assertEquals("signer-token", gateway.signerToken);
    }

    @Test
    void rejectsSha384Hash() {
        assertThrows(PscSigningException.class, () -> provider.signHash(new byte[48], "signer-token"));
    }

    @Test
    void cachesSignerCertificate() {
        X509Certificate first = provider.getSignerCertificate("signer-token");
        X509Certificate second = provider.getSignerCertificate("signer-token");

        assertSame(certificate, first);
        assertSame(first, second);
        assertEquals(1, gateway.certificateFetches);
    }

    private static final class RecordingGateway implements BryGateway {

        private final X509Certificate certificate;
        private List<byte[]> signedHashes = List.of();
        private String signerToken;
        private int certificateFetches;

        private RecordingGateway(X509Certificate certificate) {
            this.certificate = certificate;
        }

        @Override
        public List<byte[]> signCmsHashes(String signerToken, List<byte[]> documentHashes) {
            this.signerToken = signerToken;
            this.signedHashes = new ArrayList<>(documentHashes);
            return List.of(new byte[] {9, 8, 7});
        }

        @Override
        public X509Certificate fetchCertificate(String signerToken) {
            certificateFetches++;
            return certificate;
        }

        @Override
        public BryAuthorizationLink createAuthorizationLink(BryAuthorizationRequest request) {
            return new BryAuthorizationLink("signer-token", "https://psc.example/authorize");
        }
    }
}
