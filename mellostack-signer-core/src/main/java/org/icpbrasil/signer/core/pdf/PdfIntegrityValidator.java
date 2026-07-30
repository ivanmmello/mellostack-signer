package org.icpbrasil.signer.core.pdf;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.util.List;

/**
 * Valida integridade estrutural de PDFs preparados ou assinados.
 */
public final class PdfIntegrityValidator {

    private PdfIntegrityValidator() {
    }

    public static boolean isReadablePdf(byte[] pdfBytes) {
        if (pdfBytes == null || pdfBytes.length == 0) {
            return false;
        }

        try (PDDocument document = Loader.loadPDF(pdfBytes)) {
            return document.getNumberOfPages() > 0;
        } catch (IOException e) {
            return false;
        }
    }

    public static boolean hasSignatureField(byte[] pdfBytes) {
        try (PDDocument document = Loader.loadPDF(pdfBytes)) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            return signatures != null && !signatures.isEmpty();
        } catch (IOException e) {
            return false;
        }
    }

    public static void validateAfterInjection(byte[] pdfBytes) {
        if (!isReadablePdf(pdfBytes)) {
            throw new IllegalStateException("PDF is not readable after signature injection");
        }
        if (!hasSignatureField(pdfBytes)) {
            throw new IllegalStateException("PDF has no signature dictionary after injection");
        }

        int[] byteRange = ByteRangeSupport.parseByteRange(pdfBytes);
        ByteRangeSupport.resolveContentsSlot(byteRange);
    }
}
