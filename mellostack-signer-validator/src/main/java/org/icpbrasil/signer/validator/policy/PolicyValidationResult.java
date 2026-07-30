package org.icpbrasil.signer.validator.policy;

import java.util.List;
import java.util.Objects;

/**
 * Resultado da validação de política DOC-ICP-15.
 */
public record PolicyValidationResult(List<PolicyViolation> violations) {

    public PolicyValidationResult {
        violations = List.copyOf(Objects.requireNonNull(violations, "violations"));
    }

    public boolean isCompliant() {
        return violations.isEmpty();
    }

    public static PolicyValidationResult compliant() {
        return new PolicyValidationResult(List.of());
    }

    public static PolicyValidationResult of(PolicyViolation violation) {
        return new PolicyValidationResult(List.of(violation));
    }

    public static PolicyValidationResult of(List<PolicyViolation> violations) {
        return new PolicyValidationResult(violations);
    }
}
