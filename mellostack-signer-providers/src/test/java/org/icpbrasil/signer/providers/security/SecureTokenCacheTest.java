package org.icpbrasil.signer.providers.security;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureTokenCacheTest {

    @Test
    void cachesValueUntilTtlExpires() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        SecureTokenCache<String> cache = new SecureTokenCache<>(Duration.ofMinutes(5), clock);

        cache.put("access-token", "cert", "value");
        assertEquals(Optional.of("value"), cache.get("access-token", "cert"));

        clock.advance(Duration.ofMinutes(6));
        assertTrue(cache.get("access-token", "cert").isEmpty());
    }

    @Test
    void invalidateRemovesEntry() {
        SecureTokenCache<String> cache = new SecureTokenCache<>(Duration.ofMinutes(5));
        cache.put("token", "ns", "x");
        cache.invalidate("token", "ns");
        assertTrue(cache.get("token", "ns").isEmpty());
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
