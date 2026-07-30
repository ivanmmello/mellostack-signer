package org.icpbrasil.signer.core.crypto;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.core.pdf.TestPdfFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DocumentDigestCalculatorTest {

    private byte[] samplePdf;
    private PadesSignaturePreparer preparer;

    @BeforeEach
    void setUp() throws Exception {
        samplePdf = TestPdfFactory.createSamplePdf();
        preparer = new PadesSignaturePreparer();
    }

    @Test
    void computesSha256OverByteRange() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());

        byte[] digest = DocumentDigestCalculator.computeSha256(
                prepared.getPreparedPdf(),
                prepared.getByteRange()
        );

        assertEquals(32, digest.length);
        assertArrayEquals(prepared.getDocumentHash(), digest);
    }

    @Test
    void computesSha384OverByteRange() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder()
                .digestAlgorithm(DigestAlgorithm.SHA384)
                .build());

        byte[] digest = DocumentDigestCalculator.computeSha384(
                prepared.getPreparedPdf(),
                prepared.getByteRange()
        );

        assertEquals(48, digest.length);
        assertArrayEquals(prepared.getDocumentHash(), digest);
    }

    @Test
    void createPscPayloadContainsOnlyHash() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());

        HashPayload payload = DocumentDigestCalculator.createPscPayload(prepared);

        assertNotNull(payload.getDigest());
        assertEquals(DigestAlgorithm.SHA256, payload.getAlgorithm());
        assertArrayEquals(prepared.getDocumentHash(), payload.getDigest());
    }

    @Test
    void validatedPayloadRechecksDigest() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());

        HashPayload payload = DocumentDigestCalculator.createValidatedPscPayload(prepared);

        assertEquals(prepared.toPscPayload(), payload);
    }

    @Test
    void rejectsInvalidDigestLengthForAlgorithm() {
        assertThrows(IllegalArgumentException.class,
                () -> HashPayload.of(new byte[16], DigestAlgorithm.SHA256));
    }
}
