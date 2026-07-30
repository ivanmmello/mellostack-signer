package org.icpbrasil.signer.validator.act;

/**
 * Erro ao solicitar carimbo do tempo a uma ACT.
 */
public class ActException extends RuntimeException {

    public ActException(String message) {
        super(message);
    }

    public ActException(String message, Throwable cause) {
        super(message, cause);
    }
}
