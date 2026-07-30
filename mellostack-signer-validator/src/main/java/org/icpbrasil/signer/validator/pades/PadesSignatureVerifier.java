package org.icpbrasil.signer.validator.pades;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.icpbrasil.signer.core.pdf.ByteRangeSupport;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.validator.policy.DocIcp15PolicyValidator;
import org.icpbrasil.signer.validator.policy.PolicyValidationResult;

import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;

/**
 * Verificador local de assinatura PAdES (pré-validação antes da entrega ao cliente).
 */
public final class PadesSignatureVerifier {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private PadesSignatureVerifier() {
    }

    public static PadesValidationResult verify(byte[] signedPdfBytes) {
        Objects.requireNonNull(signedPdfBytes, "signedPdfBytes");
        if (signedPdfBytes.length == 0) {
            throw new PadesValidationException("signedPdfBytes must not be empty");
        }

        try {
            PadesCmsExtractor.ExtractedPadesSignature extracted = PadesCmsExtractor.extract(signedPdfBytes);
            CMSSignedData signedData = new CMSSignedData(
                    new CMSProcessableByteArray(extracted.signedContent()),
                    extracted.cmsBytes()
            );

            SignerInformation signer = singleSigner(signedData.getSignerInfos());
            X509Certificate signerCertificate = resolveSignerCertificate(signedData, signer);

            int[] byteRange = ByteRangeSupport.parseByteRange(signedPdfBytes);
            DigestAlgorithm digestAlgorithm = digestAlgorithmFromSigner(signer);
            if (digestAlgorithm == null) {
                throw new PadesValidationException("Unsupported digest algorithm in CMS signer info");
            }
            byte[] documentHash = ByteRangeSupport.computeDigest(signedPdfBytes, byteRange, digestAlgorithm);

            boolean signatureValid = verifyCloudSignature(
                    signerCertificate,
                    documentHash,
                    signer.getSignature(),
                    digestAlgorithm
            );

            PolicyValidationResult policyResult = DocIcp15PolicyValidator.validateSignerInformation(
                    signer,
                    signerCertificate,
                    documentHash
            );

            return new PadesValidationResult(
                    signatureValid,
                    policyResult.isCompliant(),
                    policyResult,
                    signerCertificate,
                    hasTimestamp(signer),
                    hasLtvData(signer)
            );
        } catch (PadesValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new PadesValidationException("Failed to verify PAdES signature", e);
        }
    }

    public static boolean isValid(byte[] signedPdfBytes) {
        try {
            return verify(signedPdfBytes).isValid();
        } catch (PadesValidationException e) {
            return false;
        }
    }

    private static SignerInformation singleSigner(SignerInformationStore store) {
        Collection<SignerInformation> signers = store.getSigners();
        if (signers.isEmpty()) {
            throw new PadesValidationException("CMS envelope does not contain signer information");
        }
        return signers.iterator().next();
    }

    private static X509Certificate resolveSignerCertificate(CMSSignedData signedData, SignerInformation signer)
            throws Exception {
        var matches = signedData.getCertificates().getMatches(signer.getSID());
        if (matches.isEmpty()) {
            throw new PadesValidationException("Signer certificate not found in CMS");
        }
        X509CertificateHolder holder = (X509CertificateHolder) matches.iterator().next();
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    private static boolean hasTimestamp(SignerInformation signer) {
        return signer.getUnsignedAttributes() != null
                && signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null;
    }

    private static boolean hasLtvData(SignerInformation signer) {
        return signer.getUnsignedAttributes() != null
                && signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null;
    }

    private static boolean verifyCloudSignature(
            X509Certificate signerCertificate,
            byte[] documentHash,
            byte[] signatureValue,
            DigestAlgorithm digestAlgorithm) throws Exception {
        if (signatureValue == null || signatureValue.length == 0) {
            return false;
        }
        String algorithm = switch (digestAlgorithm) {
            case SHA256 -> "SHA256withRSA";
            case SHA384 -> "SHA384withRSA";
        };
        Signature signature = Signature.getInstance(algorithm, "BC");
        signature.initVerify(signerCertificate.getPublicKey());
        signature.update(documentHash);
        return signature.verify(signatureValue);
    }

    private static DigestAlgorithm digestAlgorithmFromSigner(SignerInformation signer) {
        if (signer.getDigestAlgorithmID() == null) {
            return null;
        }
        if (org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256.equals(signer.getDigestAlgorithmID().getAlgorithm())) {
            return DigestAlgorithm.SHA256;
        }
        if (org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha384.equals(signer.getDigestAlgorithmID().getAlgorithm())) {
            return DigestAlgorithm.SHA384;
        }
        return null;
    }
}
