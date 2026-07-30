package org.icpbrasil.signer.providers.remoteid;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.csc.HashAlgorithmOid;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.security.SecureTokenCache;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Driver PSC Certisign Remote ID — OAuth2 + assinatura RAW via API REST (padrão ITI).
 */
public final class RemoteIdProvider implements PSCProvider {

    static final Duration CERTIFICATE_CACHE_TTL = Duration.ofMinutes(5);

    private final Environment environment;
    private final String apiBaseUrl;
    private final RemoteIdGateway apiClient;
    private final RemoteIdOAuth2Support oauth2Support;
    private final String configuredCertificateAlias;
    private final SecureTokenCache<RemoteIdApiClient.RemoteIdCertificate> certificateCache;

    RemoteIdProvider(
            Environment environment,
            String apiBaseUrl,
            RemoteIdGateway apiClient,
            RemoteIdOAuth2Support oauth2Support,
            String configuredCertificateAlias,
            SecureTokenCache<RemoteIdApiClient.RemoteIdCertificate> certificateCache) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.apiBaseUrl = Objects.requireNonNull(apiBaseUrl, "apiBaseUrl");
        this.apiClient = Objects.requireNonNull(apiClient, "apiClient");
        this.oauth2Support = Objects.requireNonNull(oauth2Support, "oauth2Support");
        this.configuredCertificateAlias = configuredCertificateAlias;
        this.certificateCache = Objects.requireNonNull(certificateCache, "certificateCache");
    }

    @Override
    public String getProviderId() {
        return "remoteid";
    }

    @Override
    public Environment getEnvironment() {
        return environment;
    }

    /**
     * URL base da API Remote ID configurada pelo integrador Certisign.
     */
    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    @Override
    public byte[] signHash(byte[] documentHash, String accessToken) {
        RemoteIdApiClient.validateDocumentHash(documentHash);
        RemoteIdApiClient.validateAccessToken(accessToken);

        String alias = resolveCertificateAlias(accessToken);
        return apiClient.signHash(
                accessToken,
                alias,
                documentHash,
                HashAlgorithmOid.fromHashLength(documentHash.length)
        );
    }

    @Override
    public X509Certificate getSignerCertificate(String accessToken) {
        return resolveCertificate(accessToken).certificate();
    }

    /**
     * Suporte OAuth2 para a aplicação host (PKCE, URL de autorização, troca de token).
     */
    public RemoteIdOAuth2Support oauth2() {
        return oauth2Support;
    }

    private RemoteIdApiClient.RemoteIdCertificate resolveCertificate(String accessToken) {
        Optional<RemoteIdApiClient.RemoteIdCertificate> cached =
                certificateCache.get(accessToken, "remoteid-certificate");
        if (cached.isPresent()) {
            return cached.get();
        }

        List<RemoteIdApiClient.RemoteIdCertificate> certificates = apiClient.discoverCertificates(accessToken);
        if (certificates.isEmpty()) {
            throw new PscSigningException("Remote ID did not return any signing certificate for this token");
        }

        RemoteIdApiClient.RemoteIdCertificate selected = selectCertificate(certificates);
        certificateCache.put(accessToken, "remoteid-certificate", selected);
        return selected;
    }

    private String resolveCertificateAlias(String accessToken) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return configuredCertificateAlias;
        }
        return resolveCertificate(accessToken).alias();
    }

    private RemoteIdApiClient.RemoteIdCertificate selectCertificate(
            List<RemoteIdApiClient.RemoteIdCertificate> certificates) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return certificates.stream()
                    .filter(entry -> configuredCertificateAlias.equals(entry.alias()))
                    .findFirst()
                    .orElseThrow(() -> new PscSigningException(
                            "Configured Remote ID certificate alias was not found for this token"));
        }
        if (certificates.size() > 1) {
            throw new PscSigningException(
                    "Multiple Remote ID certificates available — configure certificateAlias on RemoteIdProviderBuilder");
        }
        return certificates.get(0);
    }
}
