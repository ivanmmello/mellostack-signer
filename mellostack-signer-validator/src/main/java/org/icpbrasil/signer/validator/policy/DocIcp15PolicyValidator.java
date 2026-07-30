package org.icpbrasil.signer.validator.policy;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.cms.SignerInformation;
import org.icpbrasil.signer.core.pdf.ByteRangeSupport;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Valida conformidade DOC-ICP-15 / ICP-Brasil V12 (SHA-2, RSA ≥ 2048, atributos PAdES).
 */
public final class DocIcp15PolicyValidator {

    private static final Set<String> ALLOWED_SIGNATURE_OIDS = Set.of(
            PKCSObjectIdentifiers.rsaEncryption.getId(),
            PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
            PKCSObjectIdentifiers.sha384WithRSAEncryption.getId()
    );

    private static final Set<ASN1ObjectIdentifier> ALLOWED_DIGEST_OIDS = Set.of(
            NISTObjectIdentifiers.id_sha256,
            NISTObjectIdentifiers.id_sha384
    );

    private static final int MIN_RSA_BITS = 2048;

    private DocIcp15PolicyValidator() {
    }

    public static PolicyValidationResult validateCertificate(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        List<PolicyViolation> violations = new ArrayList<>();

        PublicKey publicKey = certificate.getPublicKey();
        if (!(publicKey instanceof RSAPublicKey rsaPublicKey)) {
            violations.add(PolicyViolation.WEAK_RSA_KEY);
        } else if (rsaPublicKey.getModulus().bitLength() < MIN_RSA_BITS) {
            violations.add(PolicyViolation.WEAK_RSA_KEY);
        }

        return violations.isEmpty() ? PolicyValidationResult.compliant() : PolicyValidationResult.of(violations);
    }

    public static PolicyValidationResult validateSignerInformation(
            SignerInformation signer,
            X509Certificate signerCertificate,
            byte[] documentHash) {
        Objects.requireNonNull(signer, "signer");
        Objects.requireNonNull(signerCertificate, "signerCertificate");
        Objects.requireNonNull(documentHash, "documentHash");

        List<PolicyViolation> violations = new ArrayList<>(validateCertificate(signerCertificate).violations());

        if (!isAllowedDigest(signer.getDigestAlgorithmID())) {
            violations.add(PolicyViolation.UNSUPPORTED_DIGEST);
        }

        if (!isAllowedSignatureAlgorithm(signer.getEncryptionAlgOID())) {
            violations.add(PolicyViolation.UNSUPPORTED_SIGNATURE_ALGORITHM);
        }

        if (signer.getSignedAttributes() == null) {
            violations.add(PolicyViolation.MISSING_CONTENT_TYPE);
            violations.add(PolicyViolation.MISSING_MESSAGE_DIGEST);
            violations.add(PolicyViolation.MISSING_SIGNING_TIME);
            violations.add(PolicyViolation.MISSING_SIGNING_CERTIFICATE_V2);
            return PolicyValidationResult.of(violations);
        }

        if (signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_contentType) == null) {
            violations.add(PolicyViolation.MISSING_CONTENT_TYPE);
        }
        Attribute messageDigestAttribute = signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
        if (messageDigestAttribute == null) {
            violations.add(PolicyViolation.MISSING_MESSAGE_DIGEST);
        } else if (!messageDigestMatches(messageDigestAttribute, documentHash)) {
            violations.add(PolicyViolation.MESSAGE_DIGEST_MISMATCH);
        }
        if (signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) == null) {
            violations.add(PolicyViolation.MISSING_SIGNING_TIME);
        }
        Attribute signingCertificateAttribute =
                signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
        if (signingCertificateAttribute == null) {
            violations.add(PolicyViolation.MISSING_SIGNING_CERTIFICATE_V2);
        } else if (!signingCertificateMatches(signerCertificate, signingCertificateAttribute)) {
            violations.add(PolicyViolation.SIGNING_CERTIFICATE_MISMATCH);
        }

        return violations.isEmpty() ? PolicyValidationResult.compliant() : PolicyValidationResult.of(violations);
    }

    public static void enforce(SignerInformation signer, X509Certificate signerCertificate, byte[] documentHash) {
        PolicyValidationResult result = validateSignerInformation(signer, signerCertificate, documentHash);
        if (!result.isCompliant()) {
            throw new DocIcp15Exception(
                    "Signature does not comply with DOC-ICP-15: " + result.violations(),
                    result
            );
        }
    }

    private static boolean isAllowedDigest(AlgorithmIdentifier digestAlgorithm) {
        return digestAlgorithm != null && ALLOWED_DIGEST_OIDS.contains(digestAlgorithm.getAlgorithm());
    }

    private static boolean isAllowedSignatureAlgorithm(String encryptionOid) {
        if (encryptionOid == null || encryptionOid.isBlank()) {
            return false;
        }
        return ALLOWED_SIGNATURE_OIDS.contains(encryptionOid);
    }

    private static boolean messageDigestMatches(Attribute messageDigestAttribute, byte[] documentHash) {
        try {
            byte[] expected = extractOctets(messageDigestAttribute);
            return MessageDigest.isEqual(documentHash, expected);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean signingCertificateMatches(
            X509Certificate signerCertificate,
            Attribute signingCertificateAttribute) {
        try {
            SigningCertificateV2 signingCertificateV2 = SigningCertificateV2.getInstance(
                    signingCertificateAttribute.getAttrValues().getObjectAt(0)
            );
            if (signingCertificateV2.getCerts().length == 0) {
                return false;
            }
            ESSCertIDv2 essCertId = signingCertificateV2.getCerts()[0];
            DigestAlgorithm digestAlgorithm = digestAlgorithmFromEss(essCertId.getHashAlgorithm());
            if (digestAlgorithm == null) {
                return false;
            }
            byte[] certHash = digestAlgorithm.createMessageDigest().digest(signerCertificate.getEncoded());
            return MessageDigest.isEqual(certHash, essCertId.getCertHash());
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    private static DigestAlgorithm digestAlgorithmFromSigner(SignerInformation signer) {
        AlgorithmIdentifier algorithmIdentifier = signer.getDigestAlgorithmID();
        if (algorithmIdentifier == null) {
            return null;
        }
        if (NISTObjectIdentifiers.id_sha256.equals(algorithmIdentifier.getAlgorithm())) {
            return DigestAlgorithm.SHA256;
        }
        if (NISTObjectIdentifiers.id_sha384.equals(algorithmIdentifier.getAlgorithm())) {
            return DigestAlgorithm.SHA384;
        }
        return null;
    }

    private static DigestAlgorithm digestAlgorithmFromEss(AlgorithmIdentifier algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return DigestAlgorithm.SHA256;
        }
        if (NISTObjectIdentifiers.id_sha384.equals(algorithmIdentifier.getAlgorithm())) {
            return DigestAlgorithm.SHA384;
        }
        return DigestAlgorithm.SHA256;
    }

    private static byte[] extractOctets(Attribute attribute) {
        return org.bouncycastle.asn1.ASN1OctetString.getInstance(
                attribute.getAttrValues().getObjectAt(0)
        ).getOctets();
    }
}
