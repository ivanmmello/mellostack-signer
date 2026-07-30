package org.icpbrasil.signer.validator.pades;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.icpbrasil.signer.core.crypto.EncodingUtils;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * Extrai conteúdo CMS e bytes assinados de um PDF PAdES.
 */
public final class PadesCmsExtractor {

    private PadesCmsExtractor() {
    }

    public static ExtractedPadesSignature extract(byte[] signedPdfBytes) throws IOException {
        Objects.requireNonNull(signedPdfBytes, "signedPdfBytes");
        if (signedPdfBytes.length == 0) {
            throw new IllegalArgumentException("signedPdfBytes must not be empty");
        }

        try (PDDocument document = Loader.loadPDF(signedPdfBytes)) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures == null || signatures.isEmpty()) {
                throw new IllegalStateException("PDF does not contain a digital signature");
            }

            PDSignature signature = signatures.get(0);
            byte[] cmsBytes = readCmsBytes(signature, signedPdfBytes);
            byte[] signedContent = signature.getSignedContent(signedPdfBytes);
            return new ExtractedPadesSignature(cmsBytes, signedContent, signature.getName());
        }
    }

    private static byte[] readCmsBytes(PDSignature signature, byte[] signedPdfBytes) throws IOException {
        byte[] contents = signature.getContents(signedPdfBytes);
        if (contents == null || contents.length == 0) {
            contents = signature.getContents();
        }
        if (contents == null || contents.length == 0) {
            String hex = findContentsHex(signedPdfBytes);
            if (hex == null || hex.isBlank()) {
                throw new IllegalStateException("Signature /Contents not found in PDF");
            }
            contents = EncodingUtils.fromHex(hex.trim());
        }
        return normalizeCmsBytes(contents);
    }

    static byte[] normalizeCmsBytes(byte[] data) throws IOException {
        try (ASN1InputStream input = new ASN1InputStream(data)) {
            ASN1Primitive primitive = input.readObject();
            if (primitive == null) {
                throw new IOException("CMS /Contents is empty");
            }
            return primitive.getEncoded();
        }
    }

    private static String findContentsHex(byte[] signedPdfBytes) {
        String pdfText = new String(signedPdfBytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        int contentsIndex = pdfText.indexOf("/Contents <");
        if (contentsIndex < 0) {
            contentsIndex = pdfText.indexOf("/Contents<");
        }
        if (contentsIndex < 0) {
            return null;
        }
        int start = pdfText.indexOf('<', contentsIndex) + 1;
        int end = pdfText.indexOf('>', start);
        if (start <= 0 || end <= start) {
            return null;
        }
        return pdfText.substring(start, end);
    }

    public record ExtractedPadesSignature(byte[] cmsBytes, byte[] signedContent, String signatureFieldName) {
    }
}
