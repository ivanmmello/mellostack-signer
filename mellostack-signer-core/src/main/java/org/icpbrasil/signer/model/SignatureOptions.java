package org.icpbrasil.signer.model;

/**
 * Opções de assinatura PAdES para o ciclo de assinatura em nuvem.
 */
public final class SignatureOptions {

    private final String userAccessToken;
    private final String reason;
    private final String location;
    private final boolean timestamp;
    private final boolean visibleSignature;

    private SignatureOptions(Builder builder) {
        this.userAccessToken = builder.userAccessToken;
        this.reason = builder.reason;
        this.location = builder.location;
        this.timestamp = builder.timestamp;
        this.visibleSignature = builder.visibleSignature;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getUserAccessToken() {
        return userAccessToken;
    }

    public String getReason() {
        return reason;
    }

    public String getLocation() {
        return location;
    }

    public boolean isTimestamp() {
        return timestamp;
    }

    public boolean isVisibleSignature() {
        return visibleSignature;
    }

    public static final class Builder {

        private String userAccessToken;
        private String reason;
        private String location;
        private boolean timestamp;
        private boolean visibleSignature;

        public Builder withUserAccessToken(String userAccessToken) {
            this.userAccessToken = userAccessToken;
            return this;
        }

        public Builder withReason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder withLocation(String location) {
            this.location = location;
            return this;
        }

        public Builder withTimestamp(boolean timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder withVisibleSignature(boolean visibleSignature) {
            this.visibleSignature = visibleSignature;
            return this;
        }

        public SignatureOptions build() {
            return new SignatureOptions(this);
        }
    }
}
