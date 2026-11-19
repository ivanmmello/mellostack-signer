package org.icpbrasil.signer.providers.bry;

import java.util.Objects;

/**
 * Pedido de link de autenticação da Integra Bry.
 */
public final class BryAuthorizationRequest {

    static final int MIN_LIFETIME_SECONDS = 180;
    static final int MAX_LIFETIME_SECONDS = 604_800;
    static final int VIDAAS_SESSION_DOCUMENT_THRESHOLD = 20;

    private final BryPsc psc;
    private final String redirectUri;
    private final String state;
    private final BrySignatureScope scope;
    private final Integer lifetimeSeconds;
    private final Integer numberOfDocuments;
    private final String cpf;
    private final String cnpj;

    private BryAuthorizationRequest(Builder builder) {
        this.psc = builder.psc;
        this.redirectUri = builder.redirectUri;
        this.state = builder.state;
        this.scope = builder.scope;
        this.lifetimeSeconds = builder.lifetimeSeconds;
        this.numberOfDocuments = builder.numberOfDocuments;
        this.cpf = builder.cpf;
        this.cnpj = builder.cnpj;
    }

    public static Builder builder() {
        return new Builder();
    }

    public BryPsc psc() {
        return psc;
    }

    public String redirectUri() {
        return redirectUri;
    }

    public String state() {
        return state;
    }

    public BrySignatureScope scope() {
        return scope;
    }

    public Integer lifetimeSeconds() {
        return lifetimeSeconds;
    }

    public Integer numberOfDocuments() {
        return numberOfDocuments;
    }

    public String cpf() {
        return cpf;
    }

    public String cnpj() {
        return cnpj;
    }

    public static final class Builder {

        private BryPsc psc;
        private String redirectUri;
        private String state;
        private BrySignatureScope scope = BrySignatureScope.SINGLE_SIGNATURE;
        private Integer lifetimeSeconds;
        private Integer numberOfDocuments;
        private String cpf;
        private String cnpj;

        public Builder psc(BryPsc psc) {
            this.psc = psc;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder scope(BrySignatureScope scope) {
            this.scope = Objects.requireNonNull(scope, "scope");
            return this;
        }

        public Builder lifetimeSeconds(Integer lifetimeSeconds) {
            this.lifetimeSeconds = lifetimeSeconds;
            return this;
        }

        public Builder numberOfDocuments(Integer numberOfDocuments) {
            this.numberOfDocuments = numberOfDocuments;
            return this;
        }

        public Builder cpf(String cpf) {
            this.cpf = cpf;
            return this;
        }

        public Builder cnpj(String cnpj) {
            this.cnpj = cnpj;
            return this;
        }

        public BryAuthorizationRequest build() {
            if (psc == null) {
                throw new IllegalArgumentException("psc must not be null");
            }
            if (redirectUri == null || redirectUri.isBlank()) {
                throw new IllegalArgumentException("redirectUri must not be blank");
            }
            if (state == null || state.isBlank()) {
                throw new IllegalArgumentException("state must not be blank");
            }
            if (lifetimeSeconds != null
                    && (lifetimeSeconds < MIN_LIFETIME_SECONDS || lifetimeSeconds > MAX_LIFETIME_SECONDS)) {
                throw new IllegalArgumentException(
                        "lifetimeSeconds must be between " + MIN_LIFETIME_SECONDS + " and " + MAX_LIFETIME_SECONDS);
            }
            if (numberOfDocuments != null && numberOfDocuments < 1) {
                throw new IllegalArgumentException("numberOfDocuments must be positive");
            }
            boolean hasCpf = cpf != null && !cpf.isBlank();
            boolean hasCnpj = cnpj != null && !cnpj.isBlank();
            if (hasCpf && hasCnpj) {
                throw new IllegalArgumentException("cpf and cnpj cannot be used together");
            }
            if (psc == BryPsc.VIDAAS
                    && numberOfDocuments != null
                    && numberOfDocuments > VIDAAS_SESSION_DOCUMENT_THRESHOLD
                    && scope != BrySignatureScope.SIGNATURE_SESSION) {
                throw new IllegalArgumentException(
                        "VIDaaS requests above 20 documents require scope signature_session");
            }
            return new BryAuthorizationRequest(this);
        }
    }
}
