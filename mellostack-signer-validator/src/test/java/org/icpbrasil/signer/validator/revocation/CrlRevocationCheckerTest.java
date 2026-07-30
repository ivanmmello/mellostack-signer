package org.icpbrasil.signer.validator.revocation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrlRevocationCheckerTest {

    private RevocationTestCertificates.TestCertificateAuthority authority;
    private RevocationTestCertificates.StubRevocationHttpClient httpClient;
    private CrlRevocationChecker checker;

    @BeforeEach
    void setUp() throws Exception {
        authority = RevocationTestCertificates.createAuthority();
        httpClient = new RevocationTestCertificates.StubRevocationHttpClient();
        checker = new CrlRevocationChecker(httpClient);
    }

    @Test
    void returnsGoodWhenCertificateNotListedInCrl() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(2001),
                "Good Signer",
                null,
                RevocationTestCertificates.CRL_URL
        );
        httpClient.stubGet(RevocationTestCertificates.CRL_URL, RevocationTestCertificates.createEmptyCrl(authority));

        RevocationCheckResult result = checker.check(endEntity.certificate());

        assertEquals(RevocationStatus.GOOD, result.status());
        assertEquals(CrlRevocationChecker.SOURCE, result.source());
        assertTrue(result.detail().contains("not listed"));
    }

    @Test
    void returnsRevokedWhenCertificateListedInCrl() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(2002),
                "Revoked Signer",
                null,
                RevocationTestCertificates.CRL_URL
        );
        byte[] crlBytes = RevocationTestCertificates.createRevokedCrl(authority, endEntity.certificate());
        httpClient.stubGet(RevocationTestCertificates.CRL_URL, crlBytes);

        RevocationCheckResult result = checker.check(endEntity.certificate());

        assertEquals(RevocationStatus.REVOKED, result.status());
        assertTrue(result.detail().contains("listed in CRL"));
    }

    @Test
    void returnsUnknownWhenNoCrlDistributionPoint() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(2003),
                "No Cdp",
                null,
                null
        );

        RevocationCheckResult result = checker.check(endEntity.certificate());

        assertEquals(RevocationStatus.UNKNOWN, result.status());
        assertTrue(result.detail().contains("No CRL distribution point"));
    }

    @Test
    void evaluatesEmbeddedCrlBytesDirectly() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(2004),
                "Embedded Crl",
                null,
                RevocationTestCertificates.CRL_URL
        );
        byte[] crlBytes = RevocationTestCertificates.createEmptyCrl(authority);

        RevocationCheckResult result = checker.checkAgainstCrlBytes(endEntity.certificate(), crlBytes);

        assertEquals(RevocationStatus.GOOD, result.status());
    }
}
