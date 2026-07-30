package org.icpbrasil.signer.core.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

final class SigningCertificateV2Support {

    private SigningCertificateV2Support() {
    }

    @SuppressWarnings("unchecked")
    static AttributeTable enhanceAttributes(
            AttributeTable baseTable,
            byte[] messageDigest,
            X509Certificate signerCertificate,
            DigestAlgorithm digestAlgorithm) throws CertificateEncodingException {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = baseTable.toHashtable();

        attributes.put(
                PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
                new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
                        new DERSet(new DEROctetString(messageDigest))));

        attributes.put(
                PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                        new DERSet(buildSigningCertificateV2(signerCertificate, digestAlgorithm))));

        return new AttributeTable(attributes);
    }

    private static SigningCertificateV2 buildSigningCertificateV2(
            X509Certificate certificate,
            DigestAlgorithm digestAlgorithm) throws CertificateEncodingException {
        byte[] certBytes = certificate.getEncoded();
        MessageDigest certDigest = digestAlgorithm.createMessageDigest();
        byte[] certHash = certDigest.digest(certBytes);

        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(CmsEnvelopeAssembler.digestOid(digestAlgorithm));
        ESSCertIDv2 essCertId = new ESSCertIDv2(hashAlgorithm, certHash);
        return new SigningCertificateV2(new ESSCertIDv2[]{essCertId});
    }
}
