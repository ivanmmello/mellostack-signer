package org.icpbrasil.signer.providers.iti;

/**
 * Validações comuns para APIs ITI de PSC em nuvem.
 */
public final class ItiCloudPscValidation {

    private ItiCloudPscValidation() {
    }

    public static void validateAccessToken(String accessToken) {
        if (accessToken == null) {
            throw new IllegalArgumentException("accessToken must not be null");
        }
        if (accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
        if (accessToken.length() > 4096) {
            throw new IllegalArgumentException("accessToken exceeds maximum allowed length");
        }
    }

    public static void validateCertificateAlias(String certificateAlias) {
        if (certificateAlias == null) {
            throw new IllegalArgumentException("certificateAlias must not be null");
        }
        if (certificateAlias.isBlank()) {
            throw new IllegalArgumentException("certificateAlias must not be blank");
        }
        if (certificateAlias.length() > 256) {
            throw new IllegalArgumentException("certificateAlias exceeds maximum allowed length");
        }
        for (int i = 0; i < certificateAlias.length(); i++) {
            char c = certificateAlias.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                throw new IllegalArgumentException("certificateAlias contains invalid control characters");
            }
        }
    }

    public static void validateDocumentHash(byte[] documentHash) {
        if (documentHash == null) {
            throw new IllegalArgumentException("documentHash must not be null");
        }
        if (documentHash.length != 32 && documentHash.length != 48) {
            throw new IllegalArgumentException(
                    "documentHash must be 32 (SHA-256) or 48 (SHA-384) bytes");
        }
    }
}
