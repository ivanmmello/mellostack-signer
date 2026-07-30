package org.icpbrasil.signer.providers.csc;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

/**
 * OIDs de algoritmo de hash para APIs CSC / Bird ID.
 */
public final class HashAlgorithmOid {

    public static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    public static final String SHA384 = "2.16.840.1.101.3.4.2.2";

    private HashAlgorithmOid() {
    }

    public static String forDigest(DigestAlgorithm algorithm) {
        return switch (algorithm) {
            case SHA256 -> SHA256;
            case SHA384 -> SHA384;
        };
    }

    public static DigestAlgorithm fromHashLength(int hashLength) {
        return switch (hashLength) {
            case 32 -> DigestAlgorithm.SHA256;
            case 48 -> DigestAlgorithm.SHA384;
            default -> throw new IllegalArgumentException(
                    "Unsupported document hash length: " + hashLength + " bytes (expected 32 or 48)");
        };
    }
}
