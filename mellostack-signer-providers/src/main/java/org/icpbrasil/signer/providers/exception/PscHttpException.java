package org.icpbrasil.signer.providers.exception;

/**
 * Falha HTTP ao comunicar com o PSC (timeout, 4xx/5xx, resposta inválida).
 */
public final class PscHttpException extends PscException {

    private final int statusCode;

    public PscHttpException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public PscHttpException(String message, int statusCode, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
