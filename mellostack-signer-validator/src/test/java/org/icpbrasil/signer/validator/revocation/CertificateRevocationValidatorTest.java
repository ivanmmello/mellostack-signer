package org.icpbrasil.signer.validator.revocation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateRevocationValidatorTest {

    private RevocationTestCertificates.TestCertificateAuthority authority;
    private RevocationTestCertificates.StubRevocationHttpClient httpClient;

    @BeforeEach
    void setUp() throws Exception {
        authority = RevocationTestCertificates.createAuthority();
        httpClient = new RevocationTestCertificates.StubRevocationHttpClient();
    }

    @Test
    void prefersOcspAndFallsBackToCrl() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(4001),
                "Ocsp Then Crl",
                RevocationTestCertificates.OCSP_URL,
                RevocationTestCertificates.CRL_URL
        );
        httpClient.stubPost(
                RevocationTestCertificates.OCSP_URL,
                RevocationTestCertificates.createOcspGoodResponse(
                        endEntity.certificate(),
                        endEntity.issuerCertificate(),
                        authority
                )
        );

        CertificateRevocationValidator validator = CertificateRevocationValidator.builder()
                .httpClient(httpClient)
                .preferOcsp(true)
                .build();

        RevocationCheckResult result = validator.validate(
                endEntity.certificate(),
                endEntity.issuerCertificate()
        );

        assertEquals(RevocationStatus.GOOD, result.status());
        assertEquals(OcspRevocationChecker.SOURCE, result.source());
    }

    @Test
    void fallsBackToCrlWhenOcspUnknown() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(4002),
                "Crl Fallback",
                RevocationTestCertificates.OCSP_URL,
                RevocationTestCertificates.CRL_URL
        );
        httpClient.stubGet(
                RevocationTestCertificates.CRL_URL,
                RevocationTestCertificates.createEmptyCrl(authority)
        );

        CertificateRevocationValidator validator = CertificateRevocationValidator.builder()
                .httpClient(httpClient)
                .preferOcsp(true)
                .build();

        RevocationCheckResult result = validator.validate(
                endEntity.certificate(),
                endEntity.issuerCertificate()
        );

        assertEquals(RevocationStatus.GOOD, result.status());
        assertEquals(CrlRevocationChecker.SOURCE, result.source());
    }

    @Test
    void throwsWhenCertificateIsRevoked() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(4003),
                "Revoked",
                null,
                RevocationTestCertificates.CRL_URL
        );
        httpClient.stubGet(
                RevocationTestCertificates.CRL_URL,
                RevocationTestCertificates.createRevokedCrl(authority, endEntity.certificate())
        );

        CertificateRevocationValidator validator = CertificateRevocationValidator.builder()
                .httpClient(httpClient)
                .build();

        RevocationException exception = assertThrows(
                RevocationException.class,
                () -> validator.validate(endEntity.certificate(), endEntity.issuerCertificate())
        );

        assertTrue(exception.getMessage().contains("revoked"));
        assertEquals(RevocationStatus.REVOKED, exception.result().status());
    }

    @Test
    void throwsWhenFailOnUnknownAndStatusIndeterminate() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(4004),
                "Unknown",
                null,
                null
        );

        CertificateRevocationValidator validator = CertificateRevocationValidator.builder()
                .httpClient(httpClient)
                .failOnUnknown(true)
                .build();

        RevocationException exception = assertThrows(
                RevocationException.class,
                () -> validator.validate(endEntity.certificate(), endEntity.issuerCertificate())
        );

        assertTrue(exception.getMessage().contains("unknown"));
        assertEquals(RevocationStatus.UNKNOWN, exception.result().status());
    }

    @Test
    void cachesSuccessfulResultWithinTtl() throws Exception {
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(4005),
                "Cached",
                null,
                RevocationTestCertificates.CRL_URL
        );
        httpClient.stubGet(
                RevocationTestCertificates.CRL_URL,
                RevocationTestCertificates.createEmptyCrl(authority)
        );

        CertificateRevocationValidator validator = CertificateRevocationValidator.builder()
                .httpClient(httpClient)
                .cacheTtl(Duration.ofMinutes(10))
                .build();

        RevocationCheckResult first = validator.validate(endEntity.certificate(), endEntity.issuerCertificate());
        httpClient.stubGet(RevocationTestCertificates.CRL_URL, new byte[] {1, 2, 3});
        RevocationCheckResult second = validator.validate(endEntity.certificate(), endEntity.issuerCertificate());

        assertSame(first, second);
    }
}
