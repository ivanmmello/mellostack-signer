package org.icpbrasil.signer.validator;

/**
 * Validação de conformidade ICP-Brasil V12, revogação (CRL/OCSP) e LTV.
 */
public final class SignatureValidator {

    private SignatureValidator() {
    }

    /**
     * Pré-validação local de um PDF assinado antes da entrega ao cliente.
     */
    public static boolean validateSignedPdf(byte[] signedPdfBytes) {
        if (signedPdfBytes == null || signedPdfBytes.length == 0) {
            return false;
        }
        throw new UnsupportedOperationException("Validação PAdES ainda não implementada — Fase 3");
    }
}
