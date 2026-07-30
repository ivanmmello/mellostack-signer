package org.icpbrasil.signer.validator.policy;

import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DocIcp15PolicyValidatorTest {

    @Test
    void acceptsRsa2048Certificate() throws Exception {
        var credentials = TestCertificateFactory.generateRsa2048();

        PolicyValidationResult result = DocIcp15PolicyValidator.validateCertificate(credentials.certificate());

        assertTrue(result.isCompliant());
    }

    @Test
    void rejectsWeakRsaKey() throws Exception {
        var credentials = WeakCertificateFactory.generateRsa1024();

        PolicyValidationResult result = DocIcp15PolicyValidator.validateCertificate(credentials.certificate());

        assertFalse(result.isCompliant());
        assertTrue(result.violations().contains(PolicyViolation.WEAK_RSA_KEY));
    }
}
