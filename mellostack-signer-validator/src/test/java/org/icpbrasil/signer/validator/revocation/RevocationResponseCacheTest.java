package org.icpbrasil.signer.validator.revocation;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevocationResponseCacheTest {

    @Test
    void storesAndReturnsResultBeforeTtlExpires() {
        Clock clock = Clock.fixed(Instant.parse("2026-07-30T12:00:00Z"), ZoneOffset.UTC);
        RevocationResponseCache cache = new RevocationResponseCache(Duration.ofMinutes(5), clock);
        RevocationCheckResult result = new RevocationCheckResult(
                RevocationStatus.GOOD,
                "CRL",
                clock.instant(),
                "ok"
        );

        cache.put("key", result);

        assertEquals(result, cache.get("key").orElseThrow());
    }

    @Test
    void evictsExpiredEntries() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-30T12:00:00Z"));
        RevocationResponseCache cache = new RevocationResponseCache(Duration.ofMinutes(5), clock);
        RevocationCheckResult result = new RevocationCheckResult(
                RevocationStatus.GOOD,
                "OCSP",
                clock.instant(),
                "ok"
        );
        cache.put("key", result);

        clock.advance(Duration.ofMinutes(6));

        assertTrue(cache.get("key").isEmpty());
    }

    @Test
    void extractsOcspAndCrlUrlsFromCertificate() throws Exception {
        var authority = RevocationTestCertificates.createAuthority();
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(5001),
                "Endpoints",
                RevocationTestCertificates.OCSP_URL,
                RevocationTestCertificates.CRL_URL
        );

        assertEquals(
                RevocationTestCertificates.OCSP_URL,
                CertificateRevocationEndpoints.ocspUrls(endEntity.certificate()).get(0)
        );
        assertEquals(
                RevocationTestCertificates.CRL_URL,
                CertificateRevocationEndpoints.crlUrls(endEntity.certificate()).get(0)
        );
    }

    private static final class MutableClock extends Clock {

        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
