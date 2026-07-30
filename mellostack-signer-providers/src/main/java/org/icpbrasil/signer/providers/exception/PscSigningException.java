package org.icpbrasil.signer.providers.exception;

/**
 * Falha ao assinar hash no PSC (OTP inválido, certificado expirado, escopo insuficiente, etc.).
 */
public final class PscSigningException extends PscException {

    public PscSigningException(String message) {
        super(message);
    }

    public PscSigningException(String message, Throwable cause) {
        super(message, cause);
    }
}
