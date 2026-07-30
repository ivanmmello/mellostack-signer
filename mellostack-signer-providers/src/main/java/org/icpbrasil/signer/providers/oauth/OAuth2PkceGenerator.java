package org.icpbrasil.signer.providers.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * Geração PKCE (RFC 7636) para OAuth2 Authorization Code.
 */
public final class OAuth2PkceGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int VERIFIER_BYTE_LENGTH = 32;

    private OAuth2PkceGenerator() {
    }

    public static PkceChallenge generate() {
        byte[] verifierBytes = new byte[VERIFIER_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(verifierBytes);
        String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(verifierBytes);
        String codeChallenge = s256(codeVerifier);
        return new PkceChallenge(codeVerifier, codeChallenge);
    }

    public static String s256(String codeVerifier) {
        Objects.requireNonNull(codeVerifier, "codeVerifier");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public record PkceChallenge(String codeVerifier, String codeChallenge) {
    }
}
