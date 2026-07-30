package org.icpbrasil.signer.validator.revocation;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Certificados, CRL e respostas OCSP sintéticas para testes unitários.
 */
public final class RevocationTestCertificates {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    public static final String OCSP_URL = "https://ocsp.test.local/status";
    public static final String CRL_URL = "https://crl.test.local/revocation.crl";

    private RevocationTestCertificates() {
    }

    public static TestCertificateAuthority createAuthority() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        Instant now = Instant.now();
        X500Name issuer = new X500Name("CN=MelloStack Test CA");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1001),
                Date.from(now),
                Date.from(now.plus(3650, ChronoUnit.DAYS)),
                issuer,
                keyPair.getPublic()
        );
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        var signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));

        return new TestCertificateAuthority(keyPair, certificate);
    }

    public static EndEntityCertificate issueEndEntity(
            TestCertificateAuthority authority,
            BigInteger serial,
            String commonName,
            String ocspUrl,
            String crlUrl) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        KeyPair endEntityKeyPair = generator.generateKeyPair();

        Instant now = Instant.now();
        X500Name subject = new X500Name("CN=" + commonName);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(authority.certificate().getSubjectX500Principal().getName()),
                serial,
                Date.from(now),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                endEntityKeyPair.getPublic()
        );

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(endEntityKeyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(authority.certificate()));

        if (ocspUrl != null) {
            builder.addExtension(
                    Extension.authorityInfoAccess,
                    false,
                    new AuthorityInformationAccess(new AccessDescription(
                            X509ObjectIdentifiers.id_ad_ocsp,
                            new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl))
                    ))
            );
        }
        if (crlUrl != null) {
            GeneralNames names = new GeneralNames(new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    new DERIA5String(crlUrl)
            ));
            builder.addExtension(
                    Extension.cRLDistributionPoints,
                    false,
                    new CRLDistPoint(new DistributionPoint[] {
                            new DistributionPoint(
                                    new DistributionPointName(DistributionPointName.FULL_NAME, names),
                                    null,
                                    null
                            )
                    })
            );
        }

        var signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(authority.keyPair().getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));

        return new EndEntityCertificate(certificate, authority.certificate());
    }

    public static byte[] createEmptyCrl(TestCertificateAuthority authority) throws Exception {
        Instant now = Instant.now();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                new X500Name(authority.certificate().getSubjectX500Principal().getName()),
                Date.from(now)
        );
        builder.setNextUpdate(Date.from(now.plus(7, ChronoUnit.DAYS)));
        var signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(authority.keyPair().getPrivate());
        X509CRLHolder holder = builder.build(signer);
        return holder.getEncoded();
    }

    public static byte[] createRevokedCrl(
            TestCertificateAuthority authority,
            X509Certificate revokedCertificate) throws Exception {
        Instant now = Instant.now();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                new X500Name(authority.certificate().getSubjectX500Principal().getName()),
                Date.from(now)
        );
        builder.setNextUpdate(Date.from(now.plus(7, ChronoUnit.DAYS)));
        builder.addCRLEntry(revokedCertificate.getSerialNumber(), Date.from(now), org.bouncycastle.asn1.x509.CRLReason.unspecified);

        var signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(authority.keyPair().getPrivate());
        return builder.build(signer).getEncoded();
    }

    public static byte[] createOcspGoodResponse(
            X509Certificate certificate,
            X509Certificate issuerCertificate,
            TestCertificateAuthority authority) throws Exception {
        CertificateID certificateId = buildCertificateId(certificate, issuerCertificate);
        return buildOcspResponse(certificateId, CertificateStatus.GOOD, authority);
    }

    public static byte[] createOcspRevokedResponse(
            X509Certificate certificate,
            X509Certificate issuerCertificate,
            TestCertificateAuthority authority) throws Exception {
        CertificateID certificateId = buildCertificateId(certificate, issuerCertificate);
        RevokedStatus revokedStatus = new RevokedStatus(new Date(), org.bouncycastle.asn1.x509.CRLReason.unspecified);
        return buildOcspResponse(certificateId, revokedStatus, authority);
    }

    private static byte[] buildOcspResponse(
            CertificateID certificateId,
            CertificateStatus status,
            TestCertificateAuthority authority) throws Exception {
        var signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(authority.keyPair().getPrivate());
        BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(
                new RespID(new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(authority.certificate()).getSubject())
        );
        responseBuilder.addResponse(certificateId, status, new Date(), new Date());
        return new OCSPRespBuilder()
                .build(
                        OCSPRespBuilder.SUCCESSFUL,
                        responseBuilder.build(
                                signer,
                                new org.bouncycastle.cert.X509CertificateHolder[] {
                                        new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(authority.certificate())
                                },
                                new Date()
                        )
                )
                .getEncoded();
    }

    private static CertificateID buildCertificateId(
            X509Certificate certificate,
            X509Certificate issuerCertificate) throws Exception {
        return new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1),
                issuerCertificate,
                certificate.getSerialNumber()
        );
    }

    public static X509CRL parseCrl(byte[] crlBytes) throws Exception {
        return new JcaX509CRLConverter().setProvider("BC").getCRL(new X509CRLHolder(crlBytes));
    }

    public record TestCertificateAuthority(KeyPair keyPair, X509Certificate certificate) {
    }

    public record EndEntityCertificate(X509Certificate certificate, X509Certificate issuerCertificate) {
    }

    public static final class StubRevocationHttpClient implements RevocationHttpClient {

        private final Map<String, byte[]> getResponses = new ConcurrentHashMap<>();
        private final Map<String, byte[]> postResponses = new ConcurrentHashMap<>();

        public void stubGet(String url, byte[] response) {
            getResponses.put(url, response);
        }

        public void stubPost(String url, byte[] response) {
            postResponses.put(url, response);
        }

        @Override
        public byte[] get(String url) {
            byte[] response = getResponses.get(url);
            if (response == null) {
                throw new java.io.UncheckedIOException(new java.io.IOException("No stub for GET " + url));
            }
            return response;
        }

        @Override
        public byte[] post(String url, String contentType, byte[] body) {
            byte[] response = postResponses.get(url);
            if (response == null) {
                throw new java.io.UncheckedIOException(new java.io.IOException("No stub for POST " + url));
            }
            return response;
        }
    }
}
