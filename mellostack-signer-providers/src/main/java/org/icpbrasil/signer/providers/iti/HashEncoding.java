package org.icpbrasil.signer.providers.iti;

/**
 * Codificação do hash enviado ao PSC (varia por prestador).
 */
public enum HashEncoding {

    /** Hexadecimal maiúsculo — Bird ID / Soluti. */
    HEX,

    /** Base64 — SerproID e alguns PSCs. */
    BASE64
}
