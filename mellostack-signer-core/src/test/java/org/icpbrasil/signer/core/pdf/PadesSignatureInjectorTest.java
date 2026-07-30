package org.icpbrasil.signer.core.pdf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PadesSignatureInjectorTest {

    private byte[] samplePdf;
    private PadesSignaturePreparer preparer;
    private PadesSignatureInjector injector;

    @BeforeEach
    void setUp() throws Exception {
        samplePdf = TestPdfFactory.createSamplePdf();
        preparer = new PadesSignaturePreparer();
        injector = new PadesSignatureInjector();
    }

    @Test
    void injectsCmsHexIntoReservedSlot() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());
        byte[] cms = new byte[] {0x30, 0x06, 0x02, 0x01, 0x01, 0x05, 0x00};

        byte[] signedPdf = injector.inject(prepared, cms);

        assertNotEquals(0, signedPdf.length);
        assertTrue(PdfIntegrityValidator.isReadablePdf(signedPdf));
        assertTrue(PdfIntegrityValidator.hasSignatureField(signedPdf));
        assertDoesNotThrow(() -> PdfIntegrityValidator.validateAfterInjection(signedPdf));
    }

    @Test
    void injectedPdfCanBeReloadedByPdfBox() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());
        byte[] signedPdf = injector.inject(prepared, new byte[] {0x01, 0x02, 0x03, 0x04});

        assertTrue(PdfIntegrityValidator.isReadablePdf(signedPdf));
        assertEquals(1, org.apache.pdfbox.Loader.loadPDF(signedPdf).getSignatureDictionaries().size());
    }

    @Test
    void rejectsCmsLargerThanReservedSlot() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder()
                .preferredSignatureSize(1024)
                .build());

        byte[] cms = new byte[1025];
        assertThrows(IllegalArgumentException.class, () -> injector.inject(prepared, cms));
    }
}
