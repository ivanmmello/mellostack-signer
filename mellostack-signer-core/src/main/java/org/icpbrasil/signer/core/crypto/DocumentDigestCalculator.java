package org.icpbrasil.signer.core.crypto;

import org.icpbrasil.signer.core.pdf.ByteRangeSupport;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.core.pdf.PreparedSignature;

/**
 * Calcula o digest criptográfico sobre o {@code /ByteRange} PAdES.
 * <p>
 * O digest resultante é o único dado derivado do documento que deve ser
 * transmitido ao PSC para assinatura remota.
 */
public final class DocumentDigestCalculator {

    private DocumentDigestCalculator() {
    }

    public static byte[] computeSha256(byte[] pdfBytes, int[] byteRange) {
        return compute(pdfBytes, byteRange, DigestAlgorithm.SHA256);
    }

    public static byte[] computeSha384(byte[] pdfBytes, int[] byteRange) {
        return compute(pdfBytes, byteRange, DigestAlgorithm.SHA384);
    }

    public static byte[] compute(byte[] pdfBytes, int[] byteRange, DigestAlgorithm algorithm) {
        return ByteRangeSupport.computeDigest(pdfBytes, byteRange, algorithm);
    }

    /**
     * Extrai payload seguro para o PSC a partir de um PDF preparado.
     * O PDF permanece local; apenas o hash é retornado.
     */
    public static HashPayload createPscPayload(PreparedSignature prepared) {
        if (prepared == null) {
            throw new IllegalArgumentException("prepared must not be null");
        }
        return HashPayload.of(prepared.getDocumentHash(), prepared.getDigestAlgorithm());
    }

    /**
     * Recalcula e valida o digest do PDF preparado antes do envio ao PSC.
     */
    public static HashPayload createValidatedPscPayload(PreparedSignature prepared) {
        byte[] recalculated = compute(
                prepared.getPreparedPdf(),
                prepared.getByteRange(),
                prepared.getDigestAlgorithm()
        );
        if (!java.util.Arrays.equals(recalculated, prepared.getDocumentHash())) {
            throw new IllegalStateException("Prepared PDF digest mismatch — document may be corrupted");
        }
        return HashPayload.of(recalculated, prepared.getDigestAlgorithm());
    }
}
