package org.icpbrasil.signer.core.crypto;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.util.Arrays;
import java.util.Objects;

/**
 * Payload enviado ao PSC — contém <strong>apenas o digest</strong> do {@code ByteRange},
 * nunca o PDF original ou preparado.
 */
public final class HashPayload {

    private final byte[] digest;
    private final DigestAlgorithm algorithm;

    private HashPayload(byte[] digest, DigestAlgorithm algorithm) {
        this.digest = digest.clone();
        this.algorithm = algorithm;
    }

    public static HashPayload of(byte[] digest, DigestAlgorithm algorithm) {
        Objects.requireNonNull(digest, "digest");
        Objects.requireNonNull(algorithm, "algorithm");
        if (digest.length == 0) {
            throw new IllegalArgumentException("digest must not be empty");
        }
        validateDigestLength(digest, algorithm);
        return new HashPayload(digest, algorithm);
    }

    public byte[] getDigest() {
        return digest.clone();
    }

    public DigestAlgorithm getAlgorithm() {
        return algorithm;
    }

    public String toBase64() {
        return EncodingUtils.toBase64(digest);
    }

    public String toHex() {
        return EncodingUtils.toHex(digest);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof HashPayload that)) {
            return false;
        }
        return algorithm == that.algorithm && Arrays.equals(digest, that.digest);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, Arrays.hashCode(digest));
    }

    private static void validateDigestLength(byte[] digest, DigestAlgorithm algorithm) {
        int expected = switch (algorithm) {
            case SHA256 -> 32;
            case SHA384 -> 48;
        };
        if (digest.length != expected) {
            throw new IllegalArgumentException(
                    "digest length for " + algorithm + " must be " + expected + " bytes"
            );
        }
    }
}
