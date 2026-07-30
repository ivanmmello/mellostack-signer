package org.icpbrasil.signer.validator.pades;

/**
 * Falha na verificação criptográfica ou estrutural de um PDF PAdES.
 */
public final class PadesValidationException extends RuntimeException {

    public PadesValidationException(String message) {
        super(message);
    }

    public PadesValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
