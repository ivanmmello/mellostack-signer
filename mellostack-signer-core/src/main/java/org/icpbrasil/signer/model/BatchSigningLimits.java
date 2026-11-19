package org.icpbrasil.signer.model;

/**
 * Limites operacionais para assinatura em lote via PSC.
 */
public final class BatchSigningLimits {

    /** Máximo de documentos por chamada {@code signPdfBatch} / {@code signHashes}. */
    public static final int MAX_DOCUMENTS = 50;

    private BatchSigningLimits() {
    }
}
