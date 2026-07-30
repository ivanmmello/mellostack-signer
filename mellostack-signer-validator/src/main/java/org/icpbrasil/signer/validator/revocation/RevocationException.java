package org.icpbrasil.signer.validator.revocation;

/**
 * Certificado revogado ou verificação de revogação falhou de forma crítica.
 */
public class RevocationException extends RuntimeException {

    private final RevocationCheckResult result;

    public RevocationException(String message, RevocationCheckResult result) {
        super(message);
        this.result = result;
    }

    public RevocationCheckResult result() {
        return result;
    }
}
