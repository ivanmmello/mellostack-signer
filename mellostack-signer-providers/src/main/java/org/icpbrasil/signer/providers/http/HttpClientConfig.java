package org.icpbrasil.signer.providers.http;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Configuração do cliente HTTP seguro para comunicação com PSCs.
 */
public final class HttpClientConfig {

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final Duration connectTimeout;
    private final Duration requestTimeout;
    private final boolean allowInsecureHttpForTesting;

    private HttpClientConfig(Builder builder) {
        this.connectTimeout = builder.connectTimeout;
        this.requestTimeout = builder.requestTimeout;
        this.allowInsecureHttpForTesting = builder.allowInsecureHttpForTesting;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static HttpClientConfig defaults() {
        return builder().build();
    }

    public Duration connectTimeout() {
        return connectTimeout;
    }

    public Duration requestTimeout() {
        return requestTimeout;
    }

    public boolean allowInsecureHttpForTesting() {
        return allowInsecureHttpForTesting;
    }

    void validateUrl(URI uri) {
        Objects.requireNonNull(uri, "uri");
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("URL scheme is required");
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if (allowInsecureHttpForTesting && "http".equalsIgnoreCase(scheme)) {
            String host = uri.getHost();
            if (host == null) {
                throw new IllegalArgumentException("URL host is required");
            }
            if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)) {
                return;
            }
        }
        throw new IllegalArgumentException("Only HTTPS URLs are allowed for PSC communication");
    }

    public static final class Builder {

        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration requestTimeout = DEFAULT_REQUEST_TIMEOUT;
        private boolean allowInsecureHttpForTesting;

        public Builder connectTimeout(Duration connectTimeout) {
            this.connectTimeout = Objects.requireNonNull(connectTimeout, "connectTimeout");
            return this;
        }

        public Builder requestTimeout(Duration requestTimeout) {
            this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
            return this;
        }

        public Builder allowInsecureHttpForTesting(boolean allowInsecureHttpForTesting) {
            this.allowInsecureHttpForTesting = allowInsecureHttpForTesting;
            return this;
        }

        public HttpClientConfig build() {
            if (connectTimeout.isZero() || connectTimeout.isNegative()) {
                throw new IllegalArgumentException("connectTimeout must be positive");
            }
            if (requestTimeout.isZero() || requestTimeout.isNegative()) {
                throw new IllegalArgumentException("requestTimeout must be positive");
            }
            return new HttpClientConfig(this);
        }
    }
}
