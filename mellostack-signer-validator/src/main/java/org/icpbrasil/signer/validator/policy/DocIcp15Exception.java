package org.icpbrasil.signer.validator.policy;

import java.util.Objects;

/**
 * Certificado ou CMS não conforme com DOC-ICP-15 / ICP-Brasil V12.
 */
public final class DocIcp15Exception extends RuntimeException {

    private final PolicyValidationResult result;

    public DocIcp15Exception(String message, PolicyValidationResult result) {
        super(message);
        this.result = Objects.requireNonNull(result, "result");
    }

    public PolicyValidationResult result() {
        return result;
    }
}
