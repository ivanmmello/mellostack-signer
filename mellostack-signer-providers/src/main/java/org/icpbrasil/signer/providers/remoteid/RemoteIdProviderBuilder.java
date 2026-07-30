package org.icpbrasil.signer.providers.remoteid;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.iti.HashEncoding;
import org.icpbrasil.signer.providers.security.SecureTokenCache;

import java.util.Objects;

/**
 * Builder para {@link RemoteIdProvider}.
 * <p>
 * A Certisign fornece a {@code apiBaseUrl} no processo de integração — não há URLs fixas publicadas.
 * Credenciais devem ser obtidas de variáveis de ambiente ou cofre seguro.
 */
public final class RemoteIdProviderBuilder {

    private String clientId;
    private String clientSecret;
    private String apiBaseUrl;
    private Environment environment = Environment.HOMOLOGATION;
    private String certificateAlias;
    private HashEncoding hashEncoding = HashEncoding.HEX;
    private HttpClientConfig httpClientConfig = HttpClientConfig.defaults();

    public RemoteIdProviderBuilder withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public RemoteIdProviderBuilder withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    /**
     * URL base da API Remote ID (ex.: {@code https://api-hom.certisign.com.br/remoteid}).
     * Obrigatório — fornecida pela Certisign no cadastro do integrador.
     */
    public RemoteIdProviderBuilder withApiBaseUrl(String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
        return this;
    }

    public RemoteIdProviderBuilder withEnvironment(Environment environment) {
        this.environment = Objects.requireNonNull(environment, "environment");
        return this;
    }

    /**
     * Alias do certificado Remote ID. Obrigatório quando o usuário possui múltiplos certificados.
     */
    public RemoteIdProviderBuilder withCertificateAlias(String certificateAlias) {
        this.certificateAlias = certificateAlias;
        return this;
    }

    /**
     * Codificação do hash na API ({@link HashEncoding#HEX} por padrão, compatível com Bird ID).
     */
    public RemoteIdProviderBuilder withHashEncoding(HashEncoding hashEncoding) {
        this.hashEncoding = Objects.requireNonNull(hashEncoding, "hashEncoding");
        return this;
    }

    public RemoteIdProviderBuilder withHttpClientConfig(HttpClientConfig httpClientConfig) {
        this.httpClientConfig = Objects.requireNonNull(httpClientConfig, "httpClientConfig");
        return this;
    }

    public PSCProvider build() {
        validateCredentials(clientId, "clientId");
        validateCredentials(clientSecret, "clientSecret");
        RemoteIdApiClient.validateApiBaseUrl(apiBaseUrl);
        if (certificateAlias != null && !certificateAlias.isBlank()) {
            RemoteIdApiClient.validateCertificateAlias(certificateAlias);
        }

        String normalizedApiBaseUrl = apiBaseUrl.trim();
        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        RemoteIdApiClient apiClient = new RemoteIdApiClient(normalizedApiBaseUrl, httpClient, hashEncoding);
        RemoteIdOAuth2Support oauth2Support = new RemoteIdOAuth2Support(
                normalizedApiBaseUrl, clientId, clientSecret, httpClient);
        SecureTokenCache<RemoteIdApiClient.RemoteIdCertificate> cache =
                new SecureTokenCache<>(RemoteIdProvider.CERTIFICATE_CACHE_TTL);

        return new RemoteIdProvider(
                environment,
                normalizedApiBaseUrl,
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
