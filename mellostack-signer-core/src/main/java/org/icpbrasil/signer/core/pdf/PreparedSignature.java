package org.icpbrasil.signer.core.pdf;

/**
 * PDF preparado para assinatura externa em nuvem (contêiner PAdES com placeholder).
 */
public final class PreparedSignature {

    private final byte[] preparedPdf;
    private final int[] byteRange;
    private final byte[] documentHash;
    private final int contentsHexOffset;
    private final int contentsHexLength;
    private final DigestAlgorithm digestAlgorithm;

    public PreparedSignature(
            byte[] preparedPdf,
            int[] byteRange,
            byte[] documentHash,
            int contentsHexOffset,
            int contentsHexLength,
            DigestAlgorithm digestAlgorithm) {
        this.preparedPdf = preparedPdf;
        this.byteRange = byteRange;
        this.documentHash = documentHash;
        this.contentsHexOffset = contentsHexOffset;
        this.contentsHexLength = contentsHexLength;
        this.digestAlgorithm = digestAlgorithm;
    }

    public byte[] getPreparedPdf() {
        return preparedPdf;
    }

    public int[] getByteRange() {
        return byteRange;
    }

    public byte[] getDocumentHash() {
        return documentHash;
    }

    public int getContentsHexOffset() {
        return contentsHexOffset;
    }

    public int getContentsHexLength() {
        return contentsHexLength;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Payload seguro para envio ao PSC (somente hash — sem bytes do PDF).
     */
    public org.icpbrasil.signer.core.crypto.HashPayload toPscPayload() {
        return org.icpbrasil.signer.core.crypto.HashPayload.of(documentHash, digestAlgorithm);
    }
}
