package org.icpbrasil.signer.validator.revocation;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Extrai URLs de OCSP e CRL dos extensions do certificado X.509.
 */
public final class CertificateRevocationEndpoints {

    private CertificateRevocationEndpoints() {
    }

    public static List<String> ocspUrls(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extension == null) {
            return List.of();
        }
        try {
            ASN1Primitive parsed = parseExtensionValue(extension);
            AuthorityInformationAccess access = AuthorityInformationAccess.getInstance(parsed);
            List<String> urls = new ArrayList<>();
            for (AccessDescription description : access.getAccessDescriptions()) {
                if (X509ObjectIdentifiers.id_ad_ocsp.equals(description.getAccessMethod())) {
                    String url = extractUniformResourceIdentifier(description.getAccessLocation());
                    if (url != null) {
                        urls.add(url);
                    }
                }
            }
            return List.copyOf(urls);
        } catch (Exception e) {
            return List.of();
        }
    }

    public static List<String> crlUrls(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extension == null) {
            return List.of();
        }
        try {
            ASN1Primitive parsed = parseExtensionValue(extension);
            CRLDistPoint distPoint = CRLDistPoint.getInstance(parsed);
            List<String> urls = new ArrayList<>();
            for (DistributionPoint point : distPoint.getDistributionPoints()) {
                DistributionPointName name = point.getDistributionPoint();
                if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                    continue;
                }
                GeneralNames names = GeneralNames.getInstance(name.getName());
                for (GeneralName generalName : names.getNames()) {
                    String url = extractUniformResourceIdentifier(generalName);
                    if (url != null) {
                        urls.add(url);
                    }
                }
            }
            return List.copyOf(urls);
        } catch (Exception e) {
            return List.of();
        }
    }

    private static ASN1Primitive parseExtensionValue(byte[] extensionValue) throws Exception {
        try (ASN1InputStream input = new ASN1InputStream(extensionValue)) {
            ASN1OctetString octets = (ASN1OctetString) input.readObject();
            try (ASN1InputStream inner = new ASN1InputStream(octets.getOctets())) {
                return inner.readObject();
            }
        }
    }

    private static String extractUniformResourceIdentifier(GeneralName generalName) {
        if (generalName.getTagNo() != GeneralName.uniformResourceIdentifier) {
            return null;
        }
        return DERIA5String.getInstance(generalName.getName()).getString();
    }
}
