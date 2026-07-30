package org.icpbrasil.signer.core.pdf;

import org.icpbrasil.signer.model.SignatureOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PadesSignaturePreparerTest {

    private byte[] samplePdf;
    private PadesSignaturePreparer preparer;

    @BeforeEach
    void setUp() throws Exception {
        samplePdf = TestPdfFactory.createSamplePdf();
        preparer = new PadesSignaturePreparer();
    }

    @Test
    void preparesPdfWithByteRangeAndContents() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder()
                .reason("Assinatura de teste")
                .location("Sao Paulo - SP")
                .build());

        String pdfText = new String(prepared.getPreparedPdf(), StandardCharsets.ISO_8859_1);
        assertTrue(pdfText.contains("/ByteRange"));
        assertTrue(pdfText.contains("/Contents"));
        assertNotNull(prepared.getDocumentHash());
        assertEquals(32, prepared.getDocumentHash().length);
        assertEquals(DigestAlgorithm.SHA256, prepared.getDigestAlgorithm());
    }

    @Test
    void documentHashMatchesManualByteRangeCalculation() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());

        byte[] expectedHash = ByteRangeSupport.computeDigest(
                prepared.getPreparedPdf(),
                prepared.getByteRange(),
                DigestAlgorithm.SHA256
        );

        assertArrayEquals(expectedHash, prepared.getDocumentHash());
    }

    @Test
    void supportsSha384Digest() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder()
                .digestAlgorithm(DigestAlgorithm.SHA384)
                .build());

        assertEquals(DigestAlgorithm.SHA384, prepared.getDigestAlgorithm());
        assertEquals(48, prepared.getDocumentHash().length);
    }

    @Test
    void buildsOptionsFromSignatureOptions() throws Exception {
        SignatureOptions options = SignatureOptions.builder()
                .withReason("Contrato")
                .withLocation("Brasilia - DF")
                .withVisibleSignature(false)
                .build();

        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.from(options));

        assertNotNull(prepared.getPreparedPdf());
        assertTrue(PdfIntegrityValidator.isReadablePdf(prepared.getPreparedPdf()));
    }

    @Test
    void rejectsVisibleSignatureForNow() {
        assertThrows(UnsupportedOperationException.class, () -> preparer.prepare(samplePdf,
                PadesPrepareOptions.builder().visibleSignature(true).build()));
    }

    @Test
    void rejectsEmptyPdf() {
        assertThrows(IllegalArgumentException.class,
                () -> preparer.prepare(new byte[0], PadesPrepareOptions.builder().build()));
    }
}
