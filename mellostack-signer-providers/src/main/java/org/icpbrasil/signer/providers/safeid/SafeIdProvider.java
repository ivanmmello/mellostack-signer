package org.icpbrasil.signer.providers.safeid;

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
 * Driver PSC Safeweb SafeID — OAuth2 + assinatura RAW via API REST (padrão ITI, hash hex).
 */
public final class SafeIdProvider implements PSCProvider {

    static final Duration CERTIFICATE_CACHE_TTL = Duration.ofMinutes(5);

    private final Environment environment;
    private final SafeIdGateway apiClient;
    private final SafeIdOAuth2Support oauth2Support;
    private final String configuredCertificateAlias;
    private final SecureTokenCache<SafeIdApiClient.SafeIdCertificate> certificateCache;

    SafeIdProvider(
            Environment environment,
            SafeIdGateway apiClient,
            SafeIdOAuth2Support oauth2Support,
            String configuredCertificateAlias,
            SecureTokenCache<SafeIdApiClient.SafeIdCertificate> certificateCache) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.apiClient = Objects.requireNonNull(apiClient, "apiClient");
        this.oauth2Support = Objects.requireNonNull(oauth2Support, "oauth2Support");
        this.configuredCertificateAlias = configuredCertificateAlias;
        this.certificateCache = Objects.requireNonNull(certificateCache, "certificateCache");
    }

    @Override
    public String getProviderId() {
        return "safeid";
    }

    @Override
    public Environment getEnvironment() {
        return environment;
    }

    @Override
    public byte[] signHash(byte[] documentHash, String accessToken) {
        SafeIdApiClient.validateDocumentHash(documentHash);
        SafeIdApiClient.validateAccessToken(accessToken);

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
    public SafeIdOAuth2Support oauth2() {
        return oauth2Support;
    }

    private SafeIdApiClient.SafeIdCertificate resolveCertificate(String accessToken) {
        Optional<SafeIdApiClient.SafeIdCertificate> cached =
                certificateCache.get(accessToken, "safeid-certificate");
        if (cached.isPresent()) {
            return cached.get();
        }

        List<SafeIdApiClient.SafeIdCertificate> certificates = apiClient.discoverCertificates(accessToken);
        if (certificates.isEmpty()) {
            throw new PscSigningException("SafeID did not return any signing certificate for this token");
        }

        SafeIdApiClient.SafeIdCertificate selected = selectCertificate(certificates);
        certificateCache.put(accessToken, "safeid-certificate", selected);
        return selected;
    }

    private String resolveCertificateAlias(String accessToken) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return configuredCertificateAlias;
        }
        return resolveCertificate(accessToken).alias();
    }

    private SafeIdApiClient.SafeIdCertificate selectCertificate(
            List<SafeIdApiClient.SafeIdCertificate> certificates) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return certificates.stream()
                    .filter(entry -> configuredCertificateAlias.equals(entry.alias()))
                    .findFirst()
                    .orElseThrow(() -> new PscSigningException(
                            "Configured SafeID certificate alias was not found for this token"));
        }
        if (certificates.size() > 1) {
            throw new PscSigningException(
                    "Multiple SafeID certificates available — configure certificateAlias on SafeIdProviderBuilder");
        }
        return certificates.get(0);
    }
}
