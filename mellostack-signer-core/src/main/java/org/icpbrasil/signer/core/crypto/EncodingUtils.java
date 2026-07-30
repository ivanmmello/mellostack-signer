package org.icpbrasil.signer.core.crypto;

import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

/**
 * Codificação Base64 e Hex para payloads de API (OAuth2/CSC).
 */
public final class EncodingUtils {

    private EncodingUtils() {
    }

    public static String toBase64(byte[] data) {
        Objects.requireNonNull(data, "data");
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.isBlank()) {
            throw new IllegalArgumentException("encoded must not be blank");
        }
        try {
            return Base64.getDecoder().decode(encoded.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid Base64 input", e);
        }
    }

    public static String toHex(byte[] data) {
        Objects.requireNonNull(data, "data");
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte value : data) {
            builder.append(String.format(Locale.ROOT, "%02X", value));
        }
        return builder.toString();
    }

    public static byte[] fromHex(String hex) {
        Objects.requireNonNull(hex, "hex");
        String normalized = hex.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("hex must not be blank");
        }
        if ((normalized.length() & 1) != 0) {
            throw new IllegalArgumentException("hex length must be even");
        }

        byte[] result = new byte[normalized.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            result[i] = (byte) Integer.parseInt(normalized.substring(index, index + 2), 16);
        }
        return result;
    }
}
