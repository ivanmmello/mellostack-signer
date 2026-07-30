package org.icpbrasil.signer.validator.act;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/**
 * ACT local para testes (RFC 3161) — não usar em produção.
 */
public final class LocalTimestampAuthority implements TimestampAuthority {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private final TimeStampResponseGenerator responseGenerator;

    public LocalTimestampAuthority(KeyPair tsaKeyPair, X509Certificate tsaCertificate) {
        this.responseGenerator = createResponseGenerator(tsaKeyPair, tsaCertificate);
    }

    public static LocalTimestampAuthority generate() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate certificate = createTsaCertificate(keyPair);
        return new LocalTimestampAuthority(keyPair, certificate);
    }

    private static X509Certificate createTsaCertificate(KeyPair keyPair) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=MelloStack Test ACT"),
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Name("CN=MelloStack Test ACT"),
                keyPair.getPublic()
        );
        certificateBuilder.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)
        );

        var contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    @Override
    public byte[] requestTimestampToken(byte[] messageImprint, DigestAlgorithm digestAlgorithm) {
        validateImprint(messageImprint, digestAlgorithm);
        try {
            TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.setCertReq(true);
            TimeStampRequest request = requestGenerator.generate(
                    digestOid(digestAlgorithm),
                    messageImprint
            );
            TimeStampResponse response = responseGenerator.generateGrantedResponse(
                    request,
                    BigInteger.valueOf(System.nanoTime()),
                    new Date()
            );
            return response.getTimeStampToken().getEncoded();
        } catch (Exception e) {
            throw new ActException("Failed to generate local timestamp token", e);
        }
    }

    private static TimeStampResponseGenerator createResponseGenerator(
            KeyPair keyPair,
            X509Certificate certificate) {
        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                    .setProvider("BC")
                    .build();
            DigestCalculator digestCalculator = digestCalculatorProvider.get(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)
            );
            SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
                    .setProvider("BC")
                    .build("SHA256withRSA", keyPair.getPrivate(), certificate);

            TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(
                    signerInfoGenerator,
                    digestCalculator,
                    new ASN1ObjectIdentifier("1.2.3.4.5")
            );
            tokenGenerator.addCertificates(new JcaCertStore(List.of(certificate)));
            return new TimeStampResponseGenerator(tokenGenerator, TSPAlgorithms.ALLOWED);
        } catch (Exception e) {
            throw new ActException("Failed to initialize local ACT", e);
        }
    }

    private static ASN1ObjectIdentifier digestOid(DigestAlgorithm digestAlgorithm) {
        return switch (digestAlgorithm) {
            case SHA256 -> NISTObjectIdentifiers.id_sha256;
            case SHA384 -> NISTObjectIdentifiers.id_sha384;
        };
    }

    private static void validateImprint(byte[] messageImprint, DigestAlgorithm digestAlgorithm) {
        if (messageImprint == null) {
            throw new IllegalArgumentException("messageImprint must not be null");
        }
        int expected = switch (digestAlgorithm) {
            case SHA256 -> 32;
            case SHA384 -> 48;
        };
        if (messageImprint.length != expected) {
            throw new IllegalArgumentException(
                    "messageImprint length must be " + expected + " bytes for " + digestAlgorithm);
        }
    }
}
