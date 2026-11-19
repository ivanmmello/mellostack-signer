package org.icpbrasil.signer.providers.bry;

import org.icpbrasil.signer.model.BatchSigningLimits;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.security.SecureTokenCache;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Driver da Integra Bry. O HUB Signer devolve CMS/CAdES a partir do hash SHA-256.
 */
public final class BryProvider implements PSCProvider {

    static final Duration CERTIFICATE_CACHE_TTL = Duration.ofMinutes(5);

    private final Environment environment;
    private final BryGateway gateway;
    private final BryAuthorizationClient authorizationClient;
    private final SecureTokenCache<X509Certificate> certificateCache;

    BryProvider(
            Environment environment,
            BryGateway gateway,
            SecureTokenCache<X509Certificate> certificateCache) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.gateway = Objects.requireNonNull(gateway, "gateway");
        this.authorizationClient = new BryAuthorizationClient(gateway);
        this.certificateCache = Objects.requireNonNull(certificateCache, "certificateCache");
    }

    @Override
    public String getProviderId() {
        return "bry";
    }

    @Override
    public Environment getEnvironment() {
        return environment;
    }

    @Override
    public boolean supportsBatchSigning() {
        return true;
    }

    @Override
    public boolean returnsPreparedCms() {
        return true;
    }

    @Override
    public byte[] signHash(byte[] documentHash, String accessToken) {
        return signHashes(List.of(documentHash), accessToken).get(0);
    }

    @Override
    public List<byte[]> signHashes(List<byte[]> documentHashes, String accessToken) {
        validateSignerToken(accessToken);
        if (documentHashes == null || documentHashes.isEmpty()) {
            throw new IllegalArgumentException("documentHashes must not be empty");
        }
        if (documentHashes.size() > BatchSigningLimits.MAX_DOCUMENTS) {
            throw new IllegalArgumentException(
                    "documentHashes exceeds maximum batch size of " + BatchSigningLimits.MAX_DOCUMENTS);
        }
        for (byte[] documentHash : documentHashes) {
            if (documentHash == null || documentHash.length != 32) {
                throw new PscSigningException(
                        "Integra Bry CMS signing accepts SHA-256 hashes only (32 bytes)");
            }
        }
        List<byte[]> signatures = gateway.signCmsHashes(accessToken, documentHashes);
        if (signatures.size() != documentHashes.size()) {
            throw new PscSigningException("Integra Bry returned "
                    + signatures.size() + " signatures, expected " + documentHashes.size());
        }
        List<byte[]> copied = new ArrayList<>(signatures.size());
        for (byte[] signature : signatures) {
            if (signature == null || signature.length == 0) {
                throw new PscSigningException("Integra Bry returned an empty CMS signature");
            }
            copied.add(signature.clone());
        }
        return List.copyOf(copied);
    }

    @Override
    public X509Certificate getSignerCertificate(String accessToken) {
        validateSignerToken(accessToken);
        Optional<X509Certificate> cached = certificateCache.get(accessToken, "bry-certificate");
        if (cached.isPresent()) {
            return cached.get();
        }
        X509Certificate certificate = gateway.fetchCertificate(accessToken);
        if (certificate == null) {
            throw new PscSigningException("Integra Bry did not return a signer certificate");
        }
        certificateCache.put(accessToken, "bry-certificate", certificate);
        return certificate;
    }

    public BryAuthorizationClient authorization() {
        return authorizationClient;
    }

    private static void validateSignerToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
    }
}
