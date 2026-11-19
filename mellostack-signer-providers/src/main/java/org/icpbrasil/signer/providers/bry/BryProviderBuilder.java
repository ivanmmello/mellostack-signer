package org.icpbrasil.signer.providers.bry;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.security.SecureTokenCache;
import java.util.Objects;

/**
 * Builder para {@link BryProvider}.
 * <p>
 * {@code clientId} e {@code clientSecret} são da aplicação no Bry Cloud.
 * O token do signatário vem de {@link BryAuthorizationClient#createLink} e entra em
 * {@code SignatureOptions.withUserAccessToken}.
 */
public final class BryProviderBuilder {

    private String clientId;
    private String clientSecret;
    private Environment environment = Environment.HOMOLOGATION;
    private String pscServiceUrl;
    private HttpClientConfig httpClientConfig = HttpClientConfig.defaults();

    public BryProviderBuilder withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public BryProviderBuilder withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public BryProviderBuilder withEnvironment(Environment environment) {
        this.environment = Objects.requireNonNull(environment, "environment");
        return this;
    }

    /**
     * URL enviada em {@code kms_data.url}. O padrão é a base da Integra Bry do ambiente.
     */
    public BryProviderBuilder withPscServiceUrl(String pscServiceUrl) {
        this.pscServiceUrl = pscServiceUrl;
        return this;
    }

    public BryProviderBuilder withHttpClientConfig(HttpClientConfig httpClientConfig) {
        this.httpClientConfig = Objects.requireNonNull(httpClientConfig, "httpClientConfig");
        return this;
    }

    public PSCProvider build() {
        validateCredentials(clientId, "clientId");
        validateCredentials(clientSecret, "clientSecret");
        String resolvedServiceUrl = pscServiceUrl == null || pscServiceUrl.isBlank()
                ? BryEndpoints.integraBaseUrl(environment)
                : pscServiceUrl.trim();
        if (!resolvedServiceUrl.startsWith("https://")) {
            throw new IllegalArgumentException("pscServiceUrl must use https");
        }

        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        BryApiClient apiClient = new BryApiClient(
                environment,
                clientId,
                clientSecret,
                resolvedServiceUrl,
                httpClient);
        return new BryProvider(
                environment,
                apiClient,
                new SecureTokenCache<>(BryProvider.CERTIFICATE_CACHE_TTL));
    }

    /**
     * Instância concreta para a aplicação host chamar {@link BryProvider#authorization()}.
     */
    public BryProvider buildProvider() {
        return (BryProvider) build();
    }

    private static void validateCredentials(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        if (value.length() > 512) {
            throw new IllegalArgumentException(fieldName + " exceeds maximum allowed length");
        }
    }
}
