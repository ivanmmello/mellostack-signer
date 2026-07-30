package org.icpbrasil.signer.validator.revocation;

import java.time.Instant;
import java.util.Objects;

/**
 * Resultado detalhado de uma consulta CRL ou OCSP.
 */
public record RevocationCheckResult(
        RevocationStatus status,
        String source,
        Instant checkedAt,
        String detail) {

    public RevocationCheckResult {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(checkedAt, "checkedAt");
    }

    public boolean isRevoked() {
        return status == RevocationStatus.REVOKED;
    }

    public boolean isGood() {
        return status == RevocationStatus.GOOD;
    }
}
