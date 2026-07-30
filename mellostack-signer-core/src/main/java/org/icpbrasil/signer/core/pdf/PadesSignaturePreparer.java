package org.icpbrasil.signer.core.pdf;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;

/**
 * Prepara um PDF com contêiner de assinatura PAdES vazio ({@code /ByteRange} + {@code /Contents}).
 */
public final class PadesSignaturePreparer {

    public PreparedSignature prepare(byte[] pdfBytes, PadesPrepareOptions options) throws IOException {
        if (pdfBytes == null || pdfBytes.length == 0) {
            throw new IllegalArgumentException("pdfBytes must not be empty");
        }
        if (options == null) {
            throw new IllegalArgumentException("options must not be null");
        }

        try (PDDocument document = Loader.loadPDF(pdfBytes)) {
            PDSignature signature = buildSignature(options);
            SignatureOptions signatureOptions = new SignatureOptions();
            signatureOptions.setPreferredSignatureSize(options.getPreferredSignatureSize());

            SignatureInterface placeholderSigner = new PlaceholderSigner(options.getPreferredSignatureSize());
            document.addSignature(signature, placeholderSigner, signatureOptions);

            ByteArrayOutputStream output = new ByteArrayOutputStream();
            document.saveIncremental(output);
            document.close();

            byte[] preparedPdf = output.toByteArray();
            int[] byteRange = ByteRangeSupport.parseByteRange(preparedPdf);
            ByteRangeSupport.ContentsSlot slot = ByteRangeSupport.resolveContentsSlot(byteRange);
            byte[] documentHash = ByteRangeSupport.computeDigest(
                    preparedPdf,
                    byteRange,
                    options.getDigestAlgorithm()
            );

            return new PreparedSignature(
                    preparedPdf,
                    byteRange,
                    documentHash,
                    slot.hexOffset(),
                    slot.hexLength(),
                    options.getDigestAlgorithm()
            );
        }
    }

    private static PDSignature buildSignature(PadesPrepareOptions options) {
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setSignDate(Calendar.getInstance());

        if (options.getReason() != null) {
            signature.setReason(options.getReason());
        }
        if (options.getLocation() != null) {
            signature.setLocation(options.getLocation());
        }

        if (options.isVisibleSignature()) {
            throw new UnsupportedOperationException(
                    "Assinatura visível será implementada em versão futura — use visibleSignature=false"
            );
        }

        return signature;
    }

    private static final class PlaceholderSigner implements SignatureInterface {

        private final int signatureSize;

        private PlaceholderSigner(int signatureSize) {
            this.signatureSize = signatureSize;
        }

        @Override
        public byte[] sign(InputStream content) {
            try {
                content.readAllBytes();
            } catch (IOException e) {
                throw new IllegalStateException("Failed to consume signature content stream", e);
            }
            return new byte[signatureSize];
        }
    }
}
