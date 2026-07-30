package org.icpbrasil.signer.providers.safeid;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.security.SecureTokenCache;

import java.util.Objects;

/**
 * Builder para {@link SafeIdProvider}.
 * <p>
 * Credenciais são obtidas via plataforma SafeID Integração ou {@code POST /v0/oauth/application}.
 * Nunca commitar {@code clientSecret} no repositório.
 */
public final class SafeIdProviderBuilder {

    private String clientId;
    private String clientSecret;
    private Environment environment = Environment.HOMOLOGATION;
    private String certificateAlias;
    private HttpClientConfig httpClientConfig = HttpClientConfig.defaults();

    public SafeIdProviderBuilder withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public SafeIdProviderBuilder withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public SafeIdProviderBuilder withEnvironment(Environment environment) {
        this.environment = Objects.requireNonNull(environment, "environment");
        return this;
    }

    /**
     * Alias do certificado SafeID. Obrigatório quando o usuário possui múltiplos certificados.
     */
    public SafeIdProviderBuilder withCertificateAlias(String certificateAlias) {
        this.certificateAlias = certificateAlias;
        return this;
    }

    public SafeIdProviderBuilder withHttpClientConfig(HttpClientConfig httpClientConfig) {
        this.httpClientConfig = Objects.requireNonNull(httpClientConfig, "httpClientConfig");
        return this;
    }

    public PSCProvider build() {
        validateCredentials(clientId, "clientId");
        validateCredentials(clientSecret, "clientSecret");
        if (certificateAlias != null && !certificateAlias.isBlank()) {
            SafeIdApiClient.validateCertificateAlias(certificateAlias);
        }

        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        SafeIdApiClient apiClient = new SafeIdApiClient(environment, httpClient);
        SafeIdOAuth2Support oauth2Support = new SafeIdOAuth2Support(
                environment, clientId, clientSecret, httpClient);
        SecureTokenCache<SafeIdApiClient.SafeIdCertificate> cache =
                new SecureTokenCache<>(SafeIdProvider.CERTIFICATE_CACHE_TTL);

        return new SafeIdProvider(
                environment,
                apiClient,
                oauth2Support,
                certificateAlias,
                cache
        );
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
