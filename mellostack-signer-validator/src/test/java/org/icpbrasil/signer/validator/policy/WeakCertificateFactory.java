package org.icpbrasil.signer.validator.policy;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.icpbrasil.signer.core.cms.TestCertificateFactory;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

final class WeakCertificateFactory {

    private WeakCertificateFactory() {
    }

    static TestCertificateFactory.TestCredentials generateRsa1024() throws Exception {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=MelloStack Weak Test"),
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                new X500Name("CN=MelloStack Weak Test"),
                keyPair.getPublic()
        );

        var contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certificateBuilder.build(contentSigner));

        return new TestCertificateFactory.TestCredentials(keyPair, certificate);
    }
}
