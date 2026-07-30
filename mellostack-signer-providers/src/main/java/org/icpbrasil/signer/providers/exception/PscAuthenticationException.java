package org.icpbrasil.signer.providers.exception;

/**
 * Falha de autenticação OAuth2 ou token inválido/expirado.
 */
public final class PscAuthenticationException extends PscException {

    public PscAuthenticationException(String message) {
        super(message);
    }

    public PscAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
