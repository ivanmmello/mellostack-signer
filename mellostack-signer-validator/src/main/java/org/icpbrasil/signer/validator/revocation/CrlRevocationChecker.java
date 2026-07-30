package org.icpbrasil.signer.validator.revocation;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Verificação de revogação via CRL (Certificate Revocation List).
 */
public final class CrlRevocationChecker {

    static final String SOURCE = "CRL";

    private final RevocationHttpClient httpClient;

    public CrlRevocationChecker(RevocationHttpClient httpClient) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    public RevocationCheckResult check(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        List<String> crlUrls = CertificateRevocationEndpoints.crlUrls(certificate);
        if (crlUrls.isEmpty()) {
            return unknown("No CRL distribution point found in certificate");
        }

        for (String crlUrl : crlUrls) {
            RevocationCheckResult result = checkAgainstUrl(certificate, crlUrl);
            if (result.status() != RevocationStatus.UNKNOWN) {
                return result;
            }
        }
        return unknown("All CRL endpoints failed or returned inconclusive status");
    }

    RevocationCheckResult checkAgainstCrlBytes(X509Certificate certificate, byte[] crlBytes) {
        try {
            return evaluateCrl(certificate, crlBytes, "embedded-crl");
        } catch (Exception e) {
            return unknown("Failed to parse CRL: " + e.getMessage());
        }
    }

    private RevocationCheckResult checkAgainstUrl(X509Certificate certificate, String crlUrl) {
        try {
            byte[] crlBytes = httpClient.get(crlUrl);
            return evaluateCrl(certificate, crlBytes, crlUrl);
        } catch (Exception e) {
            return unknown("CRL fetch failed for " + crlUrl + ": " + e.getMessage());
        }
    }

    private RevocationCheckResult evaluateCrl(
            X509Certificate certificate,
            byte[] crlBytes,
            String source) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) factory.generateCRL(new ByteArrayInputStream(crlBytes));
        if (crl.isRevoked(certificate)) {
            return new RevocationCheckResult(
                    RevocationStatus.REVOKED,
                    SOURCE,
                    Instant.now(),
                    "Certificate serial listed in CRL (" + source + ")"
            );
        }
        return new RevocationCheckResult(
                RevocationStatus.GOOD,
                SOURCE,
                Instant.now(),
                "Certificate not listed in CRL (" + source + ")"
        );
    }

    private static RevocationCheckResult unknown(String detail) {
        return new RevocationCheckResult(RevocationStatus.UNKNOWN, SOURCE, Instant.now(), detail);
    }
}
