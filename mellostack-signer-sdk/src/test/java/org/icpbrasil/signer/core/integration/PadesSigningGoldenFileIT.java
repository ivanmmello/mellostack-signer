package org.icpbrasil.signer.core.integration;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.validator.SignatureValidator;
import org.icpbrasil.signer.validator.pades.PadesValidationResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.Signature;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integração com PDF de referência (golden file) — valida prepare → sign → verify.
 */
@Tag("integration")
class PadesSigningGoldenFileIT {

    private static byte[] goldenPdf;
    private static byte[] expectedDocumentHash;
    private static TestCertificateFactory.TestCredentials credentials;

    @BeforeAll
    static void loadGoldenResources() throws Exception {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        goldenPdf = readResource("/golden/sample-contract.pdf");
        expectedDocumentHash = EncodingUtils.fromHex(readUtf8("/golden/sample-contract.document-hash.hex").trim());
        credentials = TestCertificateFactory.generateRsa2048();
    }

    @Test
    void preparedDocumentHashMatchesGoldenReference() throws Exception {
        PreparedSignature prepared = new PadesSignaturePreparer().prepare(
                goldenPdf,
                PadesPrepareOptions.builder().build()
        );

        assertArrayEquals(expectedDocumentHash, prepared.getDocumentHash());
    }

    @Test
    void signsGoldenPdfAndPassesLocalValidation() throws Exception {
        CloudSigner signer = new CloudSigner(testProvider());
        byte[] signedPdf = signer.signPdf(goldenPdf, SignatureOptions.builder()
                .withUserAccessToken("token")
                .withReason("Golden file test")
                .build());

        PadesValidationResult result = SignatureValidator.validateSignedPdf(signedPdf);

        assertTrue(result.isValid());
        assertTrue(result.docIcpCompliant());
        assertNotNull(result.signerCertificate());
    }

    private static PSCProvider testProvider() {
        return new PSCProvider() {
            @Override
            public String getProviderId() {
                return "golden-test";
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
                    throw new IllegalStateException("Failed to sign golden hash", e);
                }
            }

            @Override
            public java.security.cert.X509Certificate getSignerCertificate(String accessToken) {
                return credentials.certificate();
            }
        };
    }

    private static byte[] readResource(String path) throws Exception {
        try (InputStream input = PadesSigningGoldenFileIT.class.getResourceAsStream(path)) {
            return Objects.requireNonNull(input, "missing resource " + path).readAllBytes();
        }
    }

    private static String readUtf8(String path) throws Exception {
        return new String(readResource(path), java.nio.charset.StandardCharsets.UTF_8);
    }
}
