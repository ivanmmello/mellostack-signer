package org.icpbrasil.signer.providers.vidaas;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.security.SecureTokenCache;

import java.util.Objects;

/**
 * Builder para {@link VidaasProvider}.
 * <p>
 * Credenciais são obtidas via {@code POST /v0/oauth/application} no ambiente Valid
 * (homologação ou produção) — nunca commitar {@code clientSecret} no repositório.
 */
public final class VidaasProviderBuilder {

    private String clientId;
    private String clientSecret;
    private Environment environment = Environment.HOMOLOGATION;
    private String certificateAlias;
    private HttpClientConfig httpClientConfig = HttpClientConfig.defaults();

    public VidaasProviderBuilder withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public VidaasProviderBuilder withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public VidaasProviderBuilder withEnvironment(Environment environment) {
        this.environment = Objects.requireNonNull(environment, "environment");
        return this;
    }

    /**
     * Alias do certificado VIDaaS. Obrigatório quando o usuário possui múltiplos certificados.
     */
    public VidaasProviderBuilder withCertificateAlias(String certificateAlias) {
        this.certificateAlias = certificateAlias;
        return this;
    }

    public VidaasProviderBuilder withHttpClientConfig(HttpClientConfig httpClientConfig) {
        this.httpClientConfig = Objects.requireNonNull(httpClientConfig, "httpClientConfig");
        return this;
    }

    public PSCProvider build() {
        validateCredentials(clientId, "clientId");
        validateCredentials(clientSecret, "clientSecret");
        if (certificateAlias != null && !certificateAlias.isBlank()) {
            VidaasApiClient.validateCertificateAlias(certificateAlias);
        }

        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        VidaasApiClient apiClient = new VidaasApiClient(environment, httpClient);
        VidaasOAuth2Support oauth2Support = new VidaasOAuth2Support(
                environment, clientId, clientSecret, httpClient);
        SecureTokenCache<VidaasApiClient.VidaasCertificate> cache =
                new SecureTokenCache<>(VidaasProvider.CERTIFICATE_CACHE_TTL);

        return new VidaasProvider(
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
