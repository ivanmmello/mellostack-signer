package org.icpbrasil.signer.providers.serproid;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.security.SecureTokenCache;

import java.util.Objects;

/**
 * Builder para {@link SerproIdProvider}.
 * <p>
 * Credenciais saem do cadastro da aplicação no SerproID. Nunca commitar {@code clientSecret}.
 */
public final class SerproIdProviderBuilder {

    private String clientId;
    private String clientSecret;
    private Environment environment = Environment.HOMOLOGATION;
    private String certificateAlias;
    private HttpClientConfig httpClientConfig = HttpClientConfig.defaults();

    public SerproIdProviderBuilder withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public SerproIdProviderBuilder withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public SerproIdProviderBuilder withEnvironment(Environment environment) {
        this.environment = Objects.requireNonNull(environment, "environment");
        return this;
    }

    /**
     * Alias do certificado. Obrigatório quando a descoberta devolver mais de um certificado.
     */
    public SerproIdProviderBuilder withCertificateAlias(String certificateAlias) {
        this.certificateAlias = certificateAlias;
        return this;
    }

    public SerproIdProviderBuilder withHttpClientConfig(HttpClientConfig httpClientConfig) {
        this.httpClientConfig = Objects.requireNonNull(httpClientConfig, "httpClientConfig");
        return this;
    }

    public PSCProvider build() {
        validateCredentials(clientId, "clientId");
        validateCredentials(clientSecret, "clientSecret");
        if (certificateAlias != null && !certificateAlias.isBlank()) {
            SerproIdApiClient.validateCertificateAlias(certificateAlias);
        }

        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        SerproIdApiClient apiClient = new SerproIdApiClient(environment, httpClient);
        SerproIdOAuth2Support oauth2Support = new SerproIdOAuth2Support(
                environment, clientId, clientSecret, httpClient);
        SecureTokenCache<SerproIdApiClient.SerproIdCertificate> cache =
                new SecureTokenCache<>(SerproIdProvider.CERTIFICATE_CACHE_TTL);

        return new SerproIdProvider(
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
