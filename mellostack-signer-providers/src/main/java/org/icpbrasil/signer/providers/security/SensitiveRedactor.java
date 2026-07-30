package org.icpbrasil.signer.providers.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Utilitários para evitar vazamento de tokens, segredos e hashes em logs ou mensagens de erro.
 */
public final class SensitiveRedactor {

    private static final Pattern BEARER_PATTERN =
            Pattern.compile("(?i)(Bearer\\s+)[A-Za-z0-9._~+/=-]+");
    private static final Pattern CLIENT_SECRET_JSON =
            Pattern.compile("(?i)(\"client_secret\"\\s*:\\s*\")([^\"]+)(\")");
    private static final Pattern ACCESS_TOKEN_JSON =
            Pattern.compile("(?i)(\"access_token\"\\s*:\\s*\")([^\"]+)(\")");

    private SensitiveRedactor() {
    }

    public static String redact(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        String redacted = BEARER_PATTERN.matcher(value).replaceAll("$1***");
        redacted = CLIENT_SECRET_JSON.matcher(redacted).replaceAll("$1***$3");
        redacted = ACCESS_TOKEN_JSON.matcher(redacted).replaceAll("$1***$3");
        return redacted;
    }

    public static String fingerprint(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("secret must not be blank");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte value : hash) {
                builder.append(String.format(Locale.ROOT, "%02x", value));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
