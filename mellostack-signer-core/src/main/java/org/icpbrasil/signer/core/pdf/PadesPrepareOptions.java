package org.icpbrasil.signer.core.pdf;

import org.icpbrasil.signer.model.SignatureOptions;

/**
 * Opções para preparação do contêiner de assinatura PAdES no PDF.
 */
public final class PadesPrepareOptions {

    private static final int DEFAULT_SIGNATURE_SIZE = 8192;

    private final String reason;
    private final String location;
    private final boolean visibleSignature;
    private final int preferredSignatureSize;
    private final DigestAlgorithm digestAlgorithm;

    private PadesPrepareOptions(Builder builder) {
        this.reason = builder.reason;
        this.location = builder.location;
        this.visibleSignature = builder.visibleSignature;
        this.preferredSignatureSize = builder.preferredSignatureSize;
        this.digestAlgorithm = builder.digestAlgorithm;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static PadesPrepareOptions from(SignatureOptions options) {
        return builder()
                .reason(options.getReason())
                .location(options.getLocation())
                .visibleSignature(options.isVisibleSignature())
                .build();
    }

    public String getReason() {
        return reason;
    }

    public String getLocation() {
        return location;
    }

    public boolean isVisibleSignature() {
        return visibleSignature;
    }

    public int getPreferredSignatureSize() {
        return preferredSignatureSize;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public static final class Builder {

        private String reason;
        private String location;
        private boolean visibleSignature;
        private int preferredSignatureSize = DEFAULT_SIGNATURE_SIZE;
        private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder location(String location) {
            this.location = location;
            return this;
        }

        public Builder visibleSignature(boolean visibleSignature) {
            this.visibleSignature = visibleSignature;
            return this;
        }

        public Builder preferredSignatureSize(int preferredSignatureSize) {
            if (preferredSignatureSize < 1024) {
                throw new IllegalArgumentException("preferredSignatureSize must be >= 1024");
            }
            this.preferredSignatureSize = preferredSignatureSize;
            return this;
        }

        public Builder digestAlgorithm(DigestAlgorithm digestAlgorithm) {
            this.digestAlgorithm = digestAlgorithm;
            return this;
        }

        public PadesPrepareOptions build() {
            return new PadesPrepareOptions(this);
        }
    }
}
