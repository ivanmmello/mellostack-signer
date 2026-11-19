package org.icpbrasil.signer.providers.serproid;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.security.SecureTokenCache;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Driver PSC SerproID — OAuth2 PKCE + assinatura RAW (hash Base64, SHA-256).
 * O PKCS#7/PAdES continua sendo montado pelo {@code CloudSigner}.
 */
public final class SerproIdProvider implements PSCProvider {

    static final Duration CERTIFICATE_CACHE_TTL = Duration.ofMinutes(5);

    private final Environment environment;
    private final SerproIdGateway apiClient;
    private final SerproIdOAuth2Support oauth2Support;
    private final String configuredCertificateAlias;
    private final SecureTokenCache<SerproIdApiClient.SerproIdCertificate> certificateCache;

    SerproIdProvider(
            Environment environment,
            SerproIdGateway apiClient,
            SerproIdOAuth2Support oauth2Support,
            String configuredCertificateAlias,
            SecureTokenCache<SerproIdApiClient.SerproIdCertificate> certificateCache) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.apiClient = Objects.requireNonNull(apiClient, "apiClient");
        this.oauth2Support = Objects.requireNonNull(oauth2Support, "oauth2Support");
        this.configuredCertificateAlias = configuredCertificateAlias;
        this.certificateCache = Objects.requireNonNull(certificateCache, "certificateCache");
    }

    @Override
    public String getProviderId() {
        return "serproid";
    }

    @Override
    public Environment getEnvironment() {
        return environment;
    }

    @Override
    public byte[] signHash(byte[] documentHash, String accessToken) {
        return signHashes(List.of(documentHash), accessToken).get(0);
    }

    @Override
    public List<byte[]> signHashes(List<byte[]> documentHashes, String accessToken) {
        SerproIdApiClient.validateAccessToken(accessToken);
        if (documentHashes == null || documentHashes.isEmpty()) {
            throw new IllegalArgumentException("documentHashes must not be empty");
        }
        if (documentHashes.size() > SerproIdEndpoints.MAX_HASHES_PER_REQUEST) {
            throw new IllegalArgumentException(
                    "SerproID accepts at most " + SerproIdEndpoints.MAX_HASHES_PER_REQUEST + " hashes per request");
        }
        for (byte[] documentHash : documentHashes) {
            SerproIdApiClient.validateDocumentHash(documentHash);
        }
        String alias = resolveCertificateAlias(accessToken);
        return apiClient.signHashes(
                accessToken,
                alias,
                documentHashes);
    }

    @Override
    public boolean supportsBatchSigning() {
        return true;
    }

    @Override
    public X509Certificate getSignerCertificate(String accessToken) {
        return resolveCertificate(accessToken).certificate();
    }

    public SerproIdOAuth2Support oauth2() {
        return oauth2Support;
    }

    private SerproIdApiClient.SerproIdCertificate resolveCertificate(String accessToken) {
        Optional<SerproIdApiClient.SerproIdCertificate> cached =
                certificateCache.get(accessToken, "serproid-certificate");
        if (cached.isPresent()) {
            return cached.get();
        }

        List<SerproIdApiClient.SerproIdCertificate> certificates = apiClient.discoverCertificates(accessToken);
        if (certificates.isEmpty()) {
            throw new PscSigningException("SerproID did not return any signing certificate for this token");
        }

        SerproIdApiClient.SerproIdCertificate selected = selectCertificate(certificates);
        certificateCache.put(accessToken, "serproid-certificate", selected);
        return selected;
    }

    private String resolveCertificateAlias(String accessToken) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return configuredCertificateAlias;
        }
        return resolveCertificate(accessToken).alias();
    }

    private SerproIdApiClient.SerproIdCertificate selectCertificate(
            List<SerproIdApiClient.SerproIdCertificate> certificates) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return certificates.stream()
                    .filter(entry -> configuredCertificateAlias.equals(entry.alias()))
                    .findFirst()
                    .orElseThrow(() -> new PscSigningException(
                            "Configured SerproID certificate alias was not found for this token"));
        }
        if (certificates.size() > 1) {
            throw new PscSigningException(
                    "Multiple SerproID certificates available — configure certificateAlias on SerproIdProviderBuilder");
        }
        return certificates.get(0);
    }
}
