package org.icpbrasil.signer.validator.cms;

import org.icpbrasil.signer.validator.revocation.CertificateRevocationEndpoints;
import org.icpbrasil.signer.validator.revocation.RevocationHttpClient;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Coleta respostas CRL/OCSP brutas para embutir no pacote CMS (LTV).
 */
public final class LtvRevocationDataCollector {

    private final RevocationHttpClient httpClient;

    public LtvRevocationDataCollector(RevocationHttpClient httpClient) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    /**
     * Coleta dados de revogação para o certificado do signatário e cadeia informada.
     *
     * @param signerCertificate certificado do signatário
     * @param certificateChain  cadeia (issuer imediato primeiro, quando disponível)
     */
    public LtvRevocationData collect(X509Certificate signerCertificate, List<X509Certificate> certificateChain) {
        Objects.requireNonNull(signerCertificate, "signerCertificate");
        Objects.requireNonNull(certificateChain, "certificateChain");

        List<byte[]> crlResponses = new ArrayList<>();
        List<byte[]> ocspResponses = new ArrayList<>();

        collectForCertificate(signerCertificate, resolveIssuer(signerCertificate, certificateChain), crlResponses, ocspResponses);

        for (X509Certificate certificate : certificateChain) {
            if (certificate.equals(signerCertificate)) {
                continue;
            }
            collectForCertificate(certificate, resolveIssuer(certificate, certificateChain), crlResponses, ocspResponses);
        }

        return new LtvRevocationData(crlResponses, ocspResponses);
    }

    private void collectForCertificate(
            X509Certificate certificate,
            X509Certificate issuerCertificate,
            List<byte[]> crlResponses,
            List<byte[]> ocspResponses) {
        if (issuerCertificate != null) {
            for (String ocspUrl : CertificateRevocationEndpoints.ocspUrls(certificate)) {
                try {
                    byte[] request = buildMinimalOcspRequest(certificate, issuerCertificate);
                    byte[] response = httpClient.post(ocspUrl, "application/ocsp-request", request);
                    ocspResponses.add(response);
                    return;
                } catch (Exception ignored) {
                    // try next endpoint or fall back to CRL
                }
            }
        }

        for (String crlUrl : CertificateRevocationEndpoints.crlUrls(certificate)) {
            try {
                crlResponses.add(httpClient.get(crlUrl));
                return;
            } catch (Exception ignored) {
                // try next endpoint
            }
        }
    }

    private static X509Certificate resolveIssuer(
            X509Certificate certificate,
            List<X509Certificate> certificateChain) {
        for (X509Certificate candidate : certificateChain) {
            if (certificate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())
                    && !certificate.equals(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static byte[] buildMinimalOcspRequest(
            X509Certificate certificate,
            X509Certificate issuerCertificate) throws Exception {
        org.bouncycastle.cert.ocsp.CertificateID certificateId = new org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID(
                new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
                        .setProvider("BC")
                        .build()
                        .get(org.bouncycastle.cert.ocsp.CertificateID.HASH_SHA1),
                issuerCertificate,
                certificate.getSerialNumber()
        );
        org.bouncycastle.cert.ocsp.OCSPReqBuilder builder = new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
        builder.addRequest(certificateId);
        return builder.build().getEncoded();
    }
}
