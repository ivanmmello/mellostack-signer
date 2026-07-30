package org.icpbrasil.signer.core.cms;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Dados necessários para montar o envelope CMS/PKCS#7 detached (PAdES-BES).
 */
public final class CmsAssemblyRequest {

    private final byte[] rawSignature;
    private final X509Certificate signerCertificate;
    private final List<X509Certificate> certificateChain;
    private final byte[] messageDigest;
    private final DigestAlgorithm digestAlgorithm;
    private final Date signingTime;

    private CmsAssemblyRequest(Builder builder) {
        this.rawSignature = builder.rawSignature;
        this.signerCertificate = builder.signerCertificate;
        this.certificateChain = List.copyOf(builder.certificateChain);
        this.messageDigest = builder.messageDigest;
        this.digestAlgorithm = builder.digestAlgorithm;
        this.signingTime = new Date(builder.signingTime.getTime());
    }

    public static Builder builder() {
        return new Builder();
    }

    public byte[] getRawSignature() {
        return rawSignature.clone();
    }

    public X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public byte[] getMessageDigest() {
        return messageDigest.clone();
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public Date getSigningTime() {
        return new Date(signingTime.getTime());
    }

    public List<X509Certificate> getAllCertificates() {
        List<X509Certificate> all = new ArrayList<>();
        all.add(signerCertificate);
        for (X509Certificate certificate : certificateChain) {
            if (!all.contains(certificate)) {
                all.add(certificate);
            }
        }
        return Collections.unmodifiableList(all);
    }

    public static final class Builder {

        private byte[] rawSignature;
        private X509Certificate signerCertificate;
        private List<X509Certificate> certificateChain = List.of();
        private byte[] messageDigest;
        private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        private Date signingTime = new Date();

        public Builder rawSignature(byte[] rawSignature) {
            this.rawSignature = rawSignature;
            return this;
        }

        public Builder signerCertificate(X509Certificate signerCertificate) {
            this.signerCertificate = signerCertificate;
            return this;
        }

        public Builder certificateChain(List<X509Certificate> certificateChain) {
            this.certificateChain = certificateChain != null ? certificateChain : List.of();
            return this;
        }

        public Builder messageDigest(byte[] messageDigest) {
            this.messageDigest = messageDigest;
            return this;
        }

        public Builder digestAlgorithm(DigestAlgorithm digestAlgorithm) {
            this.digestAlgorithm = digestAlgorithm;
            return this;
        }

        public Builder signingTime(Date signingTime) {
            this.signingTime = signingTime;
            return this;
        }

        public CmsAssemblyRequest build() {
            Objects.requireNonNull(rawSignature, "rawSignature");
            Objects.requireNonNull(signerCertificate, "signerCertificate");
            Objects.requireNonNull(messageDigest, "messageDigest");
            Objects.requireNonNull(digestAlgorithm, "digestAlgorithm");
            Objects.requireNonNull(signingTime, "signingTime");
            if (rawSignature.length == 0) {
                throw new IllegalArgumentException("rawSignature must not be empty");
            }
            if (messageDigest.length == 0) {
                throw new IllegalArgumentException("messageDigest must not be empty");
            }
            return new CmsAssemblyRequest(this);
        }
    }
}
