package org.icpbrasil.signer.core;

import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.PdfIntegrityValidator;
import org.icpbrasil.signer.core.pdf.TestPdfFactory;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudSignerTest {

    private TestCertificateFactory.TestCredentials credentials;
    private byte[] samplePdf;

    @BeforeEach
    void setUp() throws Exception {
        credentials = TestCertificateFactory.generateRsa2048();
        samplePdf = TestPdfFactory.createSamplePdf();
    }

    @Test
    void rejectsNullProvider() {
        assertThrows(IllegalArgumentException.class, () -> new CloudSigner(null));
    }

    @Test
    void rejectsMissingAccessToken() {
        var options = SignatureOptions.builder().build();
        var signer = new CloudSigner(testProvider());

        assertThrows(IllegalArgumentException.class, () -> signer.signPdf(samplePdf, options));
    }

    @Test
    void rejectsTimestampUntilPhase3() {
        var options = SignatureOptions.builder()
                .withUserAccessToken("token")
                .withTimestamp(true)
                .build();

        var signer = new CloudSigner(testProvider());
        assertThrows(UnsupportedOperationException.class, () -> signer.signPdf(samplePdf, options));
    }

    @Test
    void signsPdfEndToEnd() throws Exception {
        var options = SignatureOptions.builder()
                .withUserAccessToken("token")
                .withReason("Teste")
                .withLocation("São Paulo - SP")
                .build();

        byte[] signedPdf = new CloudSigner(testProvider()).signPdf(samplePdf, options);

        assertNotNull(signedPdf);
        assertTrue(PdfIntegrityValidator.isReadablePdf(signedPdf));
        assertDoesNotThrow(() -> PdfIntegrityValidator.validateAfterInjection(signedPdf));
    }

    @Test
    void builderCreatesOptions() {
        var options = SignatureOptions.builder()
                .withReason("Teste")
                .withLocation("São Paulo - SP")
                .withTimestamp(true)
                .withVisibleSignature(false)
                .build();

        assertNotNull(options);
    }

    private PSCProvider testProvider() {
        return new PSCProvider() {
            @Override
            public String getProviderId() {
                return "test";
            }

            @Override
            public Environment getEnvironment() {
                return Environment.HOMOLOGATION;
            }

            @Override
            public byte[] signHash(byte[] documentHash, String accessToken) {
                try {
                    Signature signature = Signature.getInstance("SHA256withRSA", "BC");
                    signature.initSign(credentials.keyPair().getPrivate());
                    signature.update(documentHash);
                    return signature.sign();
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to sign test hash", e);
                }
            }

            @Override
            public java.security.cert.X509Certificate getSignerCertificate(String accessToken) {
                return credentials.certificate();
            }
        };
    }
}
