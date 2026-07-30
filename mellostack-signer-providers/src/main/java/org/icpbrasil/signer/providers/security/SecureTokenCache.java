package org.icpbrasil.signer.providers.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cache em memória indexado por fingerprint do token — nunca armazena o token em claro.
 */
public final class SecureTokenCache<V> {

    private final Map<String, Entry<V>> store = new ConcurrentHashMap<>();
    private final Duration ttl;
    private final Clock clock;

    public SecureTokenCache(Duration ttl) {
        this(ttl, Clock.systemUTC());
    }

    SecureTokenCache(Duration ttl, Clock clock) {
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
    }

    public Optional<V> get(String accessToken, String namespace) {
        Objects.requireNonNull(accessToken, "accessToken");
        Objects.requireNonNull(namespace, "namespace");
        if (accessToken.isBlank()) {
            return Optional.empty();
        }
        String key = cacheKey(accessToken, namespace);
        Entry<V> entry = store.get(key);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.expiresAt.isBefore(clock.instant())) {
            store.remove(key);
            return Optional.empty();
        }
        return Optional.of(entry.value);
    }

    public void put(String accessToken, String namespace, V value) {
        Objects.requireNonNull(accessToken, "accessToken");
        Objects.requireNonNull(namespace, "namespace");
        Objects.requireNonNull(value, "value");
        if (accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
        String key = cacheKey(accessToken, namespace);
        store.put(key, new Entry<>(value, clock.instant().plus(ttl)));
    }

    public void invalidate(String accessToken, String namespace) {
        if (accessToken == null || accessToken.isBlank()) {
            return;
        }
        store.remove(cacheKey(accessToken, namespace));
    }

    public void clear() {
        store.clear();
    }

    private static String cacheKey(String accessToken, String namespace) {
        return namespace + ":" + SensitiveRedactor.fingerprint(accessToken);
    }

    private record Entry<V>(V value, Instant expiresAt) {
    }
}
