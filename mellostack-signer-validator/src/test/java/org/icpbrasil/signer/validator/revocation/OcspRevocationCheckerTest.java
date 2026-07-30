package org.icpbrasil.signer.validator.revocation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OcspRevocationCheckerTest {

    private RevocationTestCertificates.TestCertificateAuthority authority;
    private RevocationTestCertificates.StubRevocationHttpClient httpClient;
    private OcspRevocationChecker checker;

    @BeforeEach
    void setUp() throws Exception {
        authority = RevocationTestCertificates.createAuthority();
        httpClient = new RevocationTestCertificates.StubRevocationHttpClient();
        checker = new OcspRevocationChecker(httpClient);
    }

    @Test
    void returnsGoodWhenOcspResponderReportsGood() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(3001),
                "Ocsp Good",
                RevocationTestCertificates.OCSP_URL,
                null
        );
        byte[] ocspResponse = RevocationTestCertificates.createOcspGoodResponse(
                endEntity.certificate(),
                endEntity.issuerCertificate(),
                authority
        );
        httpClient.stubPost(RevocationTestCertificates.OCSP_URL, ocspResponse);

        RevocationCheckResult result = checker.check(endEntity.certificate(), endEntity.issuerCertificate());

        assertEquals(RevocationStatus.GOOD, result.status());
        assertEquals(OcspRevocationChecker.SOURCE, result.source());
        assertTrue(result.detail().contains("OCSP good"));
    }

    @Test
    void returnsRevokedWhenOcspResponderReportsRevoked() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(3002),
                "Ocsp Revoked",
                RevocationTestCertificates.OCSP_URL,
                null
        );
        byte[] ocspResponse = RevocationTestCertificates.createOcspRevokedResponse(
                endEntity.certificate(),
                endEntity.issuerCertificate(),
                authority
        );
        httpClient.stubPost(RevocationTestCertificates.OCSP_URL, ocspResponse);

        RevocationCheckResult result = checker.check(endEntity.certificate(), endEntity.issuerCertificate());

        assertEquals(RevocationStatus.REVOKED, result.status());
        assertTrue(result.detail().contains("OCSP revoked"));
    }

    @Test
    void returnsUnknownWhenNoOcspUrlInCertificate() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(3003),
                "No Ocsp",
                null,
                null
        );

        RevocationCheckResult result = checker.check(endEntity.certificate(), endEntity.issuerCertificate());

        assertEquals(RevocationStatus.UNKNOWN, result.status());
        assertTrue(result.detail().contains("No OCSP URL"));
    }

    @Test
    void evaluatesEmbeddedOcspResponseDirectly() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(3004),
                "Embedded Ocsp",
                RevocationTestCertificates.OCSP_URL,
                null
        );
        byte[] ocspResponse = RevocationTestCertificates.createOcspGoodResponse(
                endEntity.certificate(),
                endEntity.issuerCertificate(),
                authority
        );

        RevocationCheckResult result = checker.checkAgainstResponseBytes(
                endEntity.certificate(),
                endEntity.issuerCertificate(),
                ocspResponse
        );

        assertEquals(RevocationStatus.GOOD, result.status());
    }
}
