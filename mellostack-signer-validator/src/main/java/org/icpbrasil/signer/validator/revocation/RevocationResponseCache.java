package org.icpbrasil.signer.validator.revocation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cache TTL de respostas CRL/OCSP por certificado.
 */
public final class RevocationResponseCache {

    private final Map<String, Entry> store = new ConcurrentHashMap<>();
    private final Duration ttl;
    private final Clock clock;

    public RevocationResponseCache(Duration ttl) {
        this(ttl, Clock.systemUTC());
    }

    RevocationResponseCache(Duration ttl, Clock clock) {
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
    }

    public Optional<RevocationCheckResult> get(String cacheKey) {
        Objects.requireNonNull(cacheKey, "cacheKey");
        Entry entry = store.get(cacheKey);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.expiresAt.isBefore(clock.instant())) {
            store.remove(cacheKey);
            return Optional.empty();
        }
        return Optional.of(entry.result);
    }

    public void put(String cacheKey, RevocationCheckResult result) {
        Objects.requireNonNull(cacheKey, "cacheKey");
        Objects.requireNonNull(result, "result");
        store.put(cacheKey, new Entry(result, clock.instant().plus(ttl)));
    }

    public void clear() {
        store.clear();
    }

    static String cacheKey(String namespace, String certificateFingerprint) {
        return namespace + ":" + certificateFingerprint;
    }

    private record Entry(RevocationCheckResult result, Instant expiresAt) {
    }
}
