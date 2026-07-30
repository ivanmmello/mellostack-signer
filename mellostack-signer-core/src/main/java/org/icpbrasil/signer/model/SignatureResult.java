package org.icpbrasil.signer.model;

import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * Resultado de uma operação de assinatura digital.
 */
public final class SignatureResult {

    private final byte[] signedDocument;
    private final X509Certificate signerCertificate;
    private final Instant signedAt;

    public SignatureResult(byte[] signedDocument, X509Certificate signerCertificate, Instant signedAt) {
        this.signedDocument = signedDocument;
        this.signerCertificate = signerCertificate;
        this.signedAt = signedAt;
    }

    public byte[] getSignedDocument() {
        return signedDocument;
    }

    public X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public Instant getSignedAt() {
        return signedAt;
    }
}
