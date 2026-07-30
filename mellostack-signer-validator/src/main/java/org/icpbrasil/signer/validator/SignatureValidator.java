package org.icpbrasil.signer.validator;

import org.icpbrasil.signer.validator.pades.PadesSignatureVerifier;
import org.icpbrasil.signer.validator.pades.PadesValidationResult;
import org.icpbrasil.signer.validator.revocation.CertificateRevocationValidator;
import org.icpbrasil.signer.validator.revocation.RevocationCheckResult;
import org.icpbrasil.signer.validator.revocation.RevocationException;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Validação de conformidade ICP-Brasil V12, revogação (CRL/OCSP) e LTV.
 */
public final class SignatureValidator {

    private SignatureValidator() {
    }

    /**
     * Verifica revogação via OCSP/CRL antes da entrega do documento assinado.
     */
    public static RevocationCheckResult validateCertificateRevocation(
            X509Certificate certificate,
            X509Certificate issuerCertificate,
            CertificateRevocationValidator validator) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(validator, "validator");
        return validator.validate(certificate, issuerCertificate);
    }

    /**
     * Pré-validação local completa de um PDF assinado (criptografia + DOC-ICP-15).
     */
    public static PadesValidationResult validateSignedPdf(byte[] signedPdfBytes) {
        return PadesSignatureVerifier.verify(signedPdfBytes);
    }

    /**
     * Atalho booleano para {@link #validateSignedPdf(byte[])}.
     */
    public static boolean isSignedPdfValid(byte[] signedPdfBytes) {
        return PadesSignatureVerifier.isValid(signedPdfBytes);
    }

    /**
     * Pré-validação PAdES + revogação online do certificado do signatário.
     */
    public static PadesValidationResult validateSignedPdf(
            byte[] signedPdfBytes,
            X509Certificate issuerCertificate,
            CertificateRevocationValidator revocationValidator) {
        PadesValidationResult result = validateSignedPdf(signedPdfBytes);
        if (!result.isValid()) {
            return result;
        }
        try {
            validateCertificateRevocation(result.signerCertificate(), issuerCertificate, revocationValidator);
        } catch (RevocationException e) {
            throw e;
        }
        return result;
    }
}
