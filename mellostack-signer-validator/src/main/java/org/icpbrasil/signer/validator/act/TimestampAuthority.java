package org.icpbrasil.signer.validator.act;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

/**
 * Cliente para Autoridade de Carimbo do Tempo (ACT) credenciada ICP-Brasil (RFC 3161).
 */
public interface TimestampAuthority {

    /**
     * Solicita um {@code TimeStampToken} sobre a impressão digital ({@code messageImprint}).
     *
     * @param messageImprint hash do valor da assinatura CMS (PAdES-T)
     * @param digestAlgorithm algoritmo usado na impressão (tipicamente SHA-256)
     * @return token RFC 3161 codificado (DER)
     */
    byte[] requestTimestampToken(byte[] messageImprint, DigestAlgorithm digestAlgorithm);
}
