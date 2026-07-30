package org.icpbrasil.signer.validator.revocation;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Verificação de revogação via OCSP (Online Certificate Status Protocol).
 */
public final class OcspRevocationChecker {

    static final String SOURCE = "OCSP";
    private static final String OCSP_REQUEST = "application/ocsp-request";
    private static final String OCSP_RESPONSE = "application/ocsp-response";

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private final RevocationHttpClient httpClient;

    public OcspRevocationChecker(RevocationHttpClient httpClient) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    public RevocationCheckResult check(X509Certificate certificate, X509Certificate issuerCertificate) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(issuerCertificate, "issuerCertificate");

        List<String> ocspUrls = CertificateRevocationEndpoints.ocspUrls(certificate);
        if (ocspUrls.isEmpty()) {
            return unknown("No OCSP URL found in Authority Information Access");
        }

        for (String ocspUrl : ocspUrls) {
            RevocationCheckResult result = checkAgainstUrl(certificate, issuerCertificate, ocspUrl);
            if (result.status() != RevocationStatus.UNKNOWN) {
                return result;
            }
        }
        return unknown("All OCSP endpoints failed or returned inconclusive status");
    }

    RevocationCheckResult checkAgainstResponseBytes(
            X509Certificate certificate,
            X509Certificate issuerCertificate,
            byte[] ocspResponseBytes) {
        try {
            CertificateID certificateId = buildCertificateId(certificate, issuerCertificate);
            return evaluateResponse(certificateId, ocspResponseBytes, "embedded-ocsp");
        } catch (Exception e) {
            return unknown("Failed to parse OCSP response: " + e.getMessage());
        }
    }

    private RevocationCheckResult checkAgainstUrl(
            X509Certificate certificate,
            X509Certificate issuerCertificate,
            String ocspUrl) {
        try {
            CertificateID certificateId = buildCertificateId(certificate, issuerCertificate);
            OCSPReq request = buildRequest(certificateId);
            byte[] responseBytes = httpClient.post(ocspUrl, OCSP_REQUEST, request.getEncoded());
            return evaluateResponse(certificateId, responseBytes, ocspUrl);
        } catch (Exception e) {
            return unknown("OCSP request failed for " + ocspUrl + ": " + e.getMessage());
        }
    }

    private static OCSPReq buildRequest(CertificateID certificateId) throws Exception {
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certificateId);
        return builder.build();
    }

    private static CertificateID buildCertificateId(
            X509Certificate certificate,
            X509Certificate issuerCertificate) throws Exception {
        return new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1),
                issuerCertificate,
                certificate.getSerialNumber()
        );
    }

    private RevocationCheckResult evaluateResponse(
            CertificateID certificateId,
            byte[] responseBytes,
            String source) throws Exception {
        OCSPResp ocspResp = new OCSPResp(responseBytes);
        if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
            return unknown("OCSP responder status " + ocspResp.getStatus() + " (" + source + ")");
        }

        BasicOCSPResp basic = (BasicOCSPResp) ocspResp.getResponseObject();
        if (basic == null) {
            return unknown("OCSP response missing BasicOCSPResp (" + source + ")");
        }

        SingleResp matching = findMatchingResponse(basic, certificateId);
        if (matching == null) {
            return unknown("OCSP response did not include requested certificate (" + source + ")");
        }

        CertificateStatus status = matching.getCertStatus();
        if (status == CertificateStatus.GOOD) {
            return new RevocationCheckResult(
                    RevocationStatus.GOOD,
                    SOURCE,
                    Instant.now(),
                    "OCSP good (" + source + ")"
            );
        }
        if (status instanceof RevokedStatus revokedStatus) {
            return new RevocationCheckResult(
                    RevocationStatus.REVOKED,
                    SOURCE,
                    Instant.now(),
                    "OCSP revoked at " + revokedStatus.getRevocationTime() + " (" + source + ")"
            );
        }
        return unknown("OCSP returned unknown certificate status (" + source + ")");
    }

    private static SingleResp findMatchingResponse(BasicOCSPResp basic, CertificateID certificateId) {
        for (SingleResp response : basic.getResponses()) {
            if (response.getCertID().equals(certificateId)) {
                return response;
            }
        }
        return null;
    }

    private static RevocationCheckResult unknown(String detail) {
        return new RevocationCheckResult(RevocationStatus.UNKNOWN, SOURCE, Instant.now(), detail);
    }
}
