package org.icpbrasil.signer.providers.birdid;

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
 * Driver PSC Bird ID (Soluti) — OAuth2 + assinatura RAW via API REST.
 */
public final class BirdIdProvider implements PSCProvider {

    static final Duration CERTIFICATE_CACHE_TTL = Duration.ofMinutes(5);

    private final Environment environment;
    private final BirdIdGateway apiClient;
    private final BirdIdOAuth2Support oauth2Support;
    private final String configuredCertificateAlias;
    private final SecureTokenCache<BirdIdApiClient.BirdIdCertificate> certificateCache;

    BirdIdProvider(
            Environment environment,
            BirdIdGateway apiClient,
            BirdIdOAuth2Support oauth2Support,
            String configuredCertificateAlias,
            SecureTokenCache<BirdIdApiClient.BirdIdCertificate> certificateCache) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.apiClient = Objects.requireNonNull(apiClient, "apiClient");
        this.oauth2Support = Objects.requireNonNull(oauth2Support, "oauth2Support");
        this.configuredCertificateAlias = configuredCertificateAlias;
        this.certificateCache = Objects.requireNonNull(certificateCache, "certificateCache");
    }

    @Override
    public String getProviderId() {
        return "birdid";
    }

    @Override
    public Environment getEnvironment() {
        return environment;
    }

    @Override
    public byte[] signHash(byte[] documentHash, String accessToken) {
        BirdIdApiClient.validateDocumentHash(documentHash);
        BirdIdApiClient.validateAccessToken(accessToken);

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
    public BirdIdOAuth2Support oauth2() {
        return oauth2Support;
    }

    private BirdIdApiClient.BirdIdCertificate resolveCertificate(String accessToken) {
        Optional<BirdIdApiClient.BirdIdCertificate> cached =
                certificateCache.get(accessToken, "birdid-certificate");
        if (cached.isPresent()) {
            return cached.get();
        }

        List<BirdIdApiClient.BirdIdCertificate> certificates = apiClient.discoverCertificates(accessToken);
        if (certificates.isEmpty()) {
            throw new PscSigningException("Bird ID did not return any signing certificate for this token");
        }

        BirdIdApiClient.BirdIdCertificate selected = selectCertificate(certificates);
        certificateCache.put(accessToken, "birdid-certificate", selected);
        return selected;
    }

    private String resolveCertificateAlias(String accessToken) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return configuredCertificateAlias;
        }
        return resolveCertificate(accessToken).alias();
    }

    private BirdIdApiClient.BirdIdCertificate selectCertificate(
            List<BirdIdApiClient.BirdIdCertificate> certificates) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return certificates.stream()
                    .filter(entry -> configuredCertificateAlias.equals(entry.alias()))
                    .findFirst()
                    .orElseThrow(() -> new PscSigningException(
                            "Configured Bird ID certificate alias was not found for this token"));
        }
        if (certificates.size() > 1) {
            throw new PscSigningException(
                    "Multiple Bird ID certificates available — configure certificateAlias on BirdIdProviderBuilder");
        }
        return certificates.get(0);
    }
}
