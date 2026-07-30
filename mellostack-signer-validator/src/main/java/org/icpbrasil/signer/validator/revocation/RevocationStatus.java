package org.icpbrasil.signer.validator.revocation;

/**
 * Resultado da verificação de revogação de um certificado.
 */
public enum RevocationStatus {

    /** Certificado válido (não revogado). */
    GOOD,

    /** Certificado revogado. */
    REVOKED,

    /** Status indeterminado (OCSP/CRL indisponível ou inconclusivo). */
    UNKNOWN
}
