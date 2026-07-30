package org.icpbrasil.signer.core.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Atributos assinados CAdES/PAdES exigidos pela ICP-Brasil V12.
 */
final class PadesSignedAttributeTableGenerator implements CMSAttributeTableGenerator {

    private final byte[] messageDigest;
    private final X509Certificate signerCertificate;
    private final DigestAlgorithm digestAlgorithm;

    PadesSignedAttributeTableGenerator(
            byte[] messageDigest,
            X509Certificate signerCertificate,
            DigestAlgorithm digestAlgorithm) {
        this.messageDigest = messageDigest.clone();
        this.signerCertificate = signerCertificate;
        this.digestAlgorithm = digestAlgorithm;
    }

    @Override
    public org.bouncycastle.asn1.cms.AttributeTable getAttributes(Map parameters) {
        try {
            org.bouncycastle.asn1.cms.AttributeTable baseTable =
                    new DefaultSignedAttributeTableGenerator().getAttributes(parameters);

            return SigningCertificateV2Support.enhanceAttributes(
                    baseTable,
                    messageDigest,
                    signerCertificate,
                    digestAlgorithm
            );
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Failed to build signed attributes", e);
        }
    }
}

/**
 * Monta envelope PKCS#7/CMS detached ({@code adbe.pkcs7.detached}) para PAdES-BES/T.
 */
public final class CmsEnvelopeAssembler {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private CmsEnvelopeAssembler() {
    }

    public static byte[] assembleDetached(CmsAssemblyRequest request)
            throws CMSException, CertificateEncodingException, OperatorCreationException, IOException {
        ContentSigner contentSigner = new PrecomputedContentSigner(
                resolveSignatureAlgorithm(request.getSignerCertificate(), request.getDigestAlgorithm()),
                request.getRawSignature()
        );

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC")
                .build();

        SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder(digestCalculatorProvider)
                .setDirectSignature(false)
                .setSignedAttributeGenerator(new PadesSignedAttributeTableGenerator(
                        request.getMessageDigest(),
                        request.getSignerCertificate(),
                        request.getDigestAlgorithm()
                ))
                .build(contentSigner, new JcaX509CertificateHolder(request.getSignerCertificate()));

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificates(new JcaCertStore(request.getAllCertificates()));
        generator.addSignerInfoGenerator(signerInfoGenerator);

        CMSSignedData signedData = generator.generate(new CMSAbsentContent(), false);
        return signedData.getEncoded();
    }

    private static org.bouncycastle.asn1.x509.AlgorithmIdentifier resolveSignatureAlgorithm(
            X509Certificate certificate,
            DigestAlgorithm digestAlgorithm) {
        String algorithmName = switch (digestAlgorithm) {
            case SHA256 -> "SHA256withRSA";
            case SHA384 -> "SHA384withRSA";
        };
        return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName);
    }

    static ASN1ObjectIdentifier digestOid(DigestAlgorithm algorithm) {
        return switch (algorithm) {
            case SHA256 -> NISTObjectIdentifiers.id_sha256;
            case SHA384 -> NISTObjectIdentifiers.id_sha384;
        };
    }

    private static final class PrecomputedContentSigner implements ContentSigner {

        private final AlgorithmIdentifier algorithmIdentifier;
        private final byte[] signature;

        private PrecomputedContentSigner(AlgorithmIdentifier algorithmIdentifier, byte[] signature) {
            this.algorithmIdentifier = algorithmIdentifier;
            this.signature = signature.clone();
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algorithmIdentifier;
        }

        @Override
        public OutputStream getOutputStream() {
            return OutputStream.nullOutputStream();
        }

        @Override
        public byte[] getSignature() {
            return signature.clone();
        }
    }
}
