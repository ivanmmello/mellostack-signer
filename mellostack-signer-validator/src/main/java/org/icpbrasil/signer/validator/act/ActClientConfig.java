package org.icpbrasil.signer.validator.act;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Configuração de conexão com uma ACT (RFC 3161).
 * <p>
 * A aplicação host define a URL por tenant/ambiente — o SDK não embute endpoints de ACT.
 */
public record ActClientConfig(
        URI tsaUrl,
        Duration connectTimeout,
        Duration readTimeout,
        String policyOid) {

    private static final Duration DEFAULT_CONNECT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_READ = Duration.ofSeconds(30);

    public ActClientConfig {
        Objects.requireNonNull(tsaUrl, "tsaUrl");
        Objects.requireNonNull(connectTimeout, "connectTimeout");
        Objects.requireNonNull(readTimeout, "readTimeout");
        if (!"https".equalsIgnoreCase(tsaUrl.getScheme())) {
            throw new IllegalArgumentException("ACT TSA URL must use HTTPS");
        }
        if (connectTimeout.isNegative() || connectTimeout.isZero()) {
            throw new IllegalArgumentException("connectTimeout must be positive");
        }
        if (readTimeout.isNegative() || readTimeout.isZero()) {
            throw new IllegalArgumentException("readTimeout must be positive");
        }
    }

    public static ActClientConfig of(String tsaUrl) {
        return new ActClientConfig(
                URI.create(Objects.requireNonNull(tsaUrl, "tsaUrl")),
                DEFAULT_CONNECT,
                DEFAULT_READ,
                null
        );
    }

    public ActClientConfig withPolicyOid(String policyOid) {
        return new ActClientConfig(tsaUrl, connectTimeout, readTimeout, policyOid);
    }

    public ActClientConfig withConnectTimeout(Duration connectTimeout) {
        return new ActClientConfig(tsaUrl, connectTimeout, readTimeout, policyOid);
    }

    public ActClientConfig withReadTimeout(Duration readTimeout) {
        return new ActClientConfig(tsaUrl, connectTimeout, readTimeout, policyOid);
    }
}
