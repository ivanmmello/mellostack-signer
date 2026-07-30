package org.icpbrasil.signer.validator.pades;

import org.icpbrasil.signer.validator.policy.PolicyValidationResult;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Resultado da pré-validação local de um PDF PAdES assinado.
 */
public record PadesValidationResult(
        boolean signatureValid,
        boolean docIcpCompliant,
        PolicyValidationResult policyResult,
        X509Certificate signerCertificate,
        boolean hasTimestamp,
        boolean hasLtvData) {

    public PadesValidationResult {
        Objects.requireNonNull(policyResult, "policyResult");
    }

    public boolean isValid() {
        return signatureValid && docIcpCompliant;
    }
}
