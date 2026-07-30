package org.icpbrasil.signer.validator.policy;

/**
 * Violações detectadas na validação DOC-ICP-15 / ICP-Brasil V12.
 */
public enum PolicyViolation {

    WEAK_RSA_KEY("RSA key size must be at least 2048 bits"),
    UNSUPPORTED_DIGEST("Digest algorithm must be SHA-256 or SHA-384 (SHA-2 family)"),
    UNSUPPORTED_SIGNATURE_ALGORITHM("Signature algorithm must use SHA-2 with RSA"),
    MISSING_CONTENT_TYPE("Missing signed attribute contentType"),
    MISSING_MESSAGE_DIGEST("Missing signed attribute messageDigest"),
    MISSING_SIGNING_TIME("Missing signed attribute signingTime"),
    MISSING_SIGNING_CERTIFICATE_V2("Missing signed attribute signingCertificateV2"),
    MESSAGE_DIGEST_MISMATCH("messageDigest attribute does not match signed PDF content"),
    SIGNING_CERTIFICATE_MISMATCH("signingCertificateV2 does not match signer certificate");

    private final String defaultMessage;

    PolicyViolation(String defaultMessage) {
        this.defaultMessage = defaultMessage;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
