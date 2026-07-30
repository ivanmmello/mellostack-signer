package org.icpbrasil.signer.core;

import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;

/**
 * Fachada principal para assinatura digital qualificada em nuvem (PAdES / Cadeia V12).
 */
public final class CloudSigner {

    private final PSCProvider provider;

    public CloudSigner(PSCProvider provider) {
        if (provider == null) {
            throw new IllegalArgumentException("PSCProvider must not be null");
        }
        this.provider = provider;
    }

    /**
     * Assina um documento PDF utilizando o PSC configurado.
     *
     * @param pdfBytes bytes do PDF original
     * @param options  opções de assinatura (token OAuth2, reason, location, etc.)
     * @return bytes do PDF assinado com conformidade ICP-Brasil V12
     */
    public byte[] signPdf(byte[] pdfBytes, SignatureOptions options) {
        if (pdfBytes == null || pdfBytes.length == 0) {
            throw new IllegalArgumentException("pdfBytes must not be empty");
        }
        if (options == null) {
            throw new IllegalArgumentException("SignatureOptions must not be null");
        }
        throw new UnsupportedOperationException("Assinatura PAdES ainda não implementada — Fase 1");
    }

    public PSCProvider getProvider() {
        return provider;
    }
}
