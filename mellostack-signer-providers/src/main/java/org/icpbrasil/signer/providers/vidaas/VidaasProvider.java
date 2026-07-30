package org.icpbrasil.signer.providers.vidaas;

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
 * Driver PSC Valid VIDaaS — OAuth2 + assinatura RAW via API REST (padrão ITI, hash Base64).
 */
public final class VidaasProvider implements PSCProvider {

    static final Duration CERTIFICATE_CACHE_TTL = Duration.ofMinutes(5);

    private final Environment environment;
    private final VidaasGateway apiClient;
    private final VidaasOAuth2Support oauth2Support;
    private final String configuredCertificateAlias;
    private final SecureTokenCache<VidaasApiClient.VidaasCertificate> certificateCache;

    VidaasProvider(
            Environment environment,
            VidaasGateway apiClient,
            VidaasOAuth2Support oauth2Support,
            String configuredCertificateAlias,
            SecureTokenCache<VidaasApiClient.VidaasCertificate> certificateCache) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.apiClient = Objects.requireNonNull(apiClient, "apiClient");
        this.oauth2Support = Objects.requireNonNull(oauth2Support, "oauth2Support");
        this.configuredCertificateAlias = configuredCertificateAlias;
        this.certificateCache = Objects.requireNonNull(certificateCache, "certificateCache");
    }

    @Override
    public String getProviderId() {
        return "vidaas";
    }

    @Override
    public Environment getEnvironment() {
        return environment;
    }

    @Override
    public byte[] signHash(byte[] documentHash, String accessToken) {
        VidaasApiClient.validateDocumentHash(documentHash);
        VidaasApiClient.validateAccessToken(accessToken);

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
     * Suporte OAuth2 para a aplicação host (PKCE, QR Code, push, troca de token).
     */
    public VidaasOAuth2Support oauth2() {
        return oauth2Support;
    }

    private VidaasApiClient.VidaasCertificate resolveCertificate(String accessToken) {
        Optional<VidaasApiClient.VidaasCertificate> cached =
                certificateCache.get(accessToken, "vidaas-certificate");
        if (cached.isPresent()) {
            return cached.get();
        }

        List<VidaasApiClient.VidaasCertificate> certificates = apiClient.discoverCertificates(accessToken);
        if (certificates.isEmpty()) {
            throw new PscSigningException("VIDaaS did not return any signing certificate for this token");
        }

        VidaasApiClient.VidaasCertificate selected = selectCertificate(certificates);
        certificateCache.put(accessToken, "vidaas-certificate", selected);
        return selected;
    }

    private String resolveCertificateAlias(String accessToken) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return configuredCertificateAlias;
        }
        return resolveCertificate(accessToken).alias();
    }

    private VidaasApiClient.VidaasCertificate selectCertificate(
            List<VidaasApiClient.VidaasCertificate> certificates) {
        if (configuredCertificateAlias != null && !configuredCertificateAlias.isBlank()) {
            return certificates.stream()
                    .filter(entry -> configuredCertificateAlias.equals(entry.alias()))
                    .findFirst()
                    .orElseThrow(() -> new PscSigningException(
                            "Configured VIDaaS certificate alias was not found for this token"));
        }
        if (certificates.size() > 1) {
            throw new PscSigningException(
                    "Multiple VIDaaS certificates available — configure certificateAlias on VidaasProviderBuilder");
        }
        return certificates.get(0);
    }
}
