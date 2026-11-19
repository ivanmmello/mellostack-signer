package org.icpbrasil.signer.core;

import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.validator.SignatureValidator;
import org.icpbrasil.signer.validator.pades.PadesValidationResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudSignerBatchTest {

    private static byte[] goldenPdf;
    private static TestCertificateFactory.TestCredentials credentials;

    @BeforeAll
    static void loadResources() throws Exception {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        try (InputStream input = CloudSignerBatchTest.class.getResourceAsStream("/golden/sample-contract.pdf")) {
            goldenPdf = Objects.requireNonNull(input, "missing golden sample-contract.pdf").readAllBytes();
        }
        credentials = TestCertificateFactory.generateRsa2048();
    }

    @Test
    void signPdfBatchSignsMultipleDocumentsWithSinglePscCall() throws Exception {
        RecordingBatchProvider provider = new RecordingBatchProvider();
        CloudSigner signer = new CloudSigner(provider);

        List<byte[]> signed = signer.signPdfBatch(
                List.of(goldenPdf, goldenPdf),
                SignatureOptions.builder()
                        .withUserAccessToken("token")
                        .withReason("Batch test")
                        .build());

        assertEquals(2, signed.size());
        assertEquals(1, provider.batchCalls.get());
        assertEquals(2, provider.lastHashCount);

        for (byte[] pdf : signed) {
            PadesValidationResult result = SignatureValidator.validateSignedPdf(pdf);
            assertTrue(result.isValid());
            assertTrue(result.docIcpCompliant());
        }
    }

    @Test
    void signPdfBatchRejectsEmptyList() {
        CloudSigner signer = new CloudSigner(new RecordingBatchProvider());
        assertThrows(IllegalArgumentException.class, () -> signer.signPdfBatch(
                List.of(),
                SignatureOptions.builder().withUserAccessToken("token").build()));
    }

    private static final class RecordingBatchProvider implements PSCProvider {

        private final AtomicInteger batchCalls = new AtomicInteger();
        private int lastHashCount;

        @Override
        public String getProviderId() {
            return "batch-test";
        }

        @Override
        public Environment getEnvironment() {
            return Environment.HOMOLOGATION;
        }

        @Override
        public byte[] signHash(byte[] documentHash, String accessToken) {
            return signHashes(List.of(documentHash), accessToken).get(0);
        }

        @Override
        public List<byte[]> signHashes(List<byte[]> documentHashes, String accessToken) {
            batchCalls.incrementAndGet();
            lastHashCount = documentHashes.size();
            List<byte[]> signatures = new ArrayList<>(documentHashes.size());
            for (byte[] hash : documentHashes) {
                signatures.add(signLocally(hash));
            }
            return signatures;
        }

        @Override
        public boolean supportsBatchSigning() {
            return true;
        }

        @Override
        public java.security.cert.X509Certificate getSignerCertificate(String accessToken) {
            return credentials.certificate();
        }

        private static byte[] signLocally(byte[] hash) throws RuntimeException {
            try {
                Signature signature = Signature.getInstance("SHA256withRSA", "BC");
                signature.initSign(credentials.keyPair().getPrivate());
                signature.update(hash);
                return signature.sign();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
