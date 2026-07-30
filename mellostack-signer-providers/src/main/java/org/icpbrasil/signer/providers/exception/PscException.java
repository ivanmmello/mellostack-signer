package org.icpbrasil.signer.providers.exception;

/**
 * Exceção base para falhas de comunicação ou processamento em drivers PSC.
 */
public class PscException extends RuntimeException {

    public PscException(String message) {
        super(message);
    }

    public PscException(String message, Throwable cause) {
        super(message, cause);
    }
}
