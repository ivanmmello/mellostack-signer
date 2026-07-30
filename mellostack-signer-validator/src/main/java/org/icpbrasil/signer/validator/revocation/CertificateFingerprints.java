package org.icpbrasil.signer.validator.revocation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

final class CertificateFingerprints {

    private CertificateFingerprints() {
    }

    static String fingerprint(X509Certificate certificate) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(certificate.getIssuerX500Principal().getEncoded());
            digest.update(certificate.getSerialNumber().toByteArray());
            return toHex(digest.digest());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fingerprint certificate", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02X", value));
        }
        return builder.toString();
    }
}
