package org.icpbrasil.signer.validator.revocation;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;

/**
 * Orquestra consultas OCSP e CRL com cache configurável.
 */
public final class CertificateRevocationValidator {

    private final OcspRevocationChecker ocspChecker;
    private final CrlRevocationChecker crlChecker;
    private final RevocationResponseCache cache;
    private final boolean preferOcsp;
    private final boolean failOnUnknown;

    CertificateRevocationValidator(
            OcspRevocationChecker ocspChecker,
            CrlRevocationChecker crlChecker,
            RevocationResponseCache cache,
            boolean preferOcsp,
            boolean failOnUnknown) {
        this.ocspChecker = Objects.requireNonNull(ocspChecker, "ocspChecker");
        this.crlChecker = Objects.requireNonNull(crlChecker, "crlChecker");
        this.cache = Objects.requireNonNull(cache, "cache");
        this.preferOcsp = preferOcsp;
        this.failOnUnknown = failOnUnknown;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Verifica revogação do certificado. Lança {@link RevocationException} se revogado
     * (ou indeterminado quando {@code failOnUnknown} estiver ativo).
     */
    public RevocationCheckResult validate(X509Certificate certificate, X509Certificate issuerCertificate) {
        Objects.requireNonNull(certificate, "certificate");
        String fingerprint = CertificateFingerprints.fingerprint(certificate);
        String cacheKey = RevocationResponseCache.cacheKey("revocation", fingerprint);

        RevocationCheckResult cached = cache.get(cacheKey).orElse(null);
        if (cached != null) {
            enforcePolicy(cached, fingerprint);
            return cached;
        }

        RevocationCheckResult result = preferOcsp
                ? checkOcspThenCrl(certificate, issuerCertificate)
                : checkCrlThenOcsp(certificate, issuerCertificate);

        cache.put(cacheKey, result);
        enforcePolicy(result, fingerprint);
        return result;
    }

    private RevocationCheckResult checkOcspThenCrl(
            X509Certificate certificate,
            X509Certificate issuerCertificate) {
        if (issuerCertificate != null) {
            RevocationCheckResult ocsp = ocspChecker.check(certificate, issuerCertificate);
            if (ocsp.status() != RevocationStatus.UNKNOWN) {
                return ocsp;
            }
        }
        return crlChecker.check(certificate);
    }

    private RevocationCheckResult checkCrlThenOcsp(
            X509Certificate certificate,
            X509Certificate issuerCertificate) {
        RevocationCheckResult crl = crlChecker.check(certificate);
        if (crl.status() != RevocationStatus.UNKNOWN) {
            return crl;
        }
        if (issuerCertificate != null) {
            return ocspChecker.check(certificate, issuerCertificate);
        }
        return crl;
    }

    private void enforcePolicy(RevocationCheckResult result, String fingerprint) {
        if (result.isRevoked()) {
            throw new RevocationException(
                    "Certificate is revoked (" + result.source() + ")",
                    result
            );
        }
        if (failOnUnknown && result.status() == RevocationStatus.UNKNOWN) {
            throw new RevocationException(
                    "Certificate revocation status is unknown for fingerprint " + fingerprint,
                    result
            );
        }
    }

    public static final class Builder {

        private RevocationHttpClient httpClient = new JavaRevocationHttpClient();
        private Duration cacheTtl = Duration.ofMinutes(15);
        private boolean preferOcsp = true;
        private boolean failOnUnknown = false;

        public Builder httpClient(RevocationHttpClient httpClient) {
            this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
            return this;
        }

        public Builder cacheTtl(Duration cacheTtl) {
            this.cacheTtl = Objects.requireNonNull(cacheTtl, "cacheTtl");
            return this;
        }

        public Builder preferOcsp(boolean preferOcsp) {
            this.preferOcsp = preferOcsp;
            return this;
        }

        public Builder failOnUnknown(boolean failOnUnknown) {
            this.failOnUnknown = failOnUnknown;
            return this;
        }

        public CertificateRevocationValidator build() {
            return new CertificateRevocationValidator(
                    new OcspRevocationChecker(httpClient),
                    new CrlRevocationChecker(httpClient),
                    new RevocationResponseCache(cacheTtl),
                    preferOcsp,
                    failOnUnknown
            );
        }
    }
}
