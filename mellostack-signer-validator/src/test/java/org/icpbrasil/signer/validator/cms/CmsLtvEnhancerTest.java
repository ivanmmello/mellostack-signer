package org.icpbrasil.signer.validator.cms;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.icpbrasil.signer.core.cms.CmsAssemblyRequest;
import org.icpbrasil.signer.core.cms.CmsEnvelopeAssembler;
import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.core.pdf.TestPdfFactory;
import org.icpbrasil.signer.validator.revocation.RevocationTestCertificates;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Signature;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CmsLtvEnhancerTest {

    private TestCertificateFactory.TestCredentials credentials;
    private byte[] cmsBytes;

    @BeforeEach
    void setUp() throws Exception {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        credentials = TestCertificateFactory.generateRsa2048();
        cmsBytes = buildSampleCms();
    }

    @Test
    void embedsRevocationValuesInCms() throws Exception {
        RevocationTestCertificates.TestCertificateAuthority authority =
                RevocationTestCertificates.createAuthority();
        RevocationTestCertificates.StubRevocationHttpClient httpClient =
                new RevocationTestCertificates.StubRevocationHttpClient();
        var endEntity = RevocationTestCertificates.issueEndEntity(
                authority,
                BigInteger.valueOf(9001),
                "LTV Signer",
                null,
                RevocationTestCertificates.CRL_URL
        );
        httpClient.stubGet(
                RevocationTestCertificates.CRL_URL,
                RevocationTestCertificates.createEmptyCrl(authority)
        );

        LtvRevocationDataCollector collector = new LtvRevocationDataCollector(httpClient);
        LtvRevocationData revocationData = collector.collect(
                endEntity.certificate(),
                List.of(endEntity.issuerCertificate())
        );

        byte[] enhanced = CmsLtvEnhancer.enhance(cmsBytes, revocationData);
        CMSSignedData signedData = new CMSSignedData(enhanced);
        SignerInformation signer = signedData.getSignerInfos().getSigners().iterator().next();

        assertNotNull(signer.getUnsignedAttributes());
        assertNotNull(signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationValues));
        assertTrue(signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null);
    }

    private byte[] buildSampleCms() throws Exception {
        byte[] samplePdf = TestPdfFactory.createSamplePdf();
        PreparedSignature prepared = new PadesSignaturePreparer().prepare(
                samplePdf,
                PadesPrepareOptions.builder().build()
        );

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(credentials.keyPair().getPrivate());
        signature.update(prepared.getDocumentHash());
        byte[] rawSignature = signature.sign();

        return CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                .rawSignature(rawSignature)
                .signerCertificate(credentials.certificate())
                .messageDigest(prepared.getDocumentHash())
                .digestAlgorithm(DigestAlgorithm.SHA256)
                .signingTime(new Date())
                .build());
    }
}
