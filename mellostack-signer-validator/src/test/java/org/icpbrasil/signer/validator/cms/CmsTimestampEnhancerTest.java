package org.icpbrasil.signer.validator.cms;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.icpbrasil.signer.core.cms.CmsAssemblyRequest;
import org.icpbrasil.signer.core.cms.CmsEnvelopeAssembler;
import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.core.pdf.TestPdfFactory;
import org.icpbrasil.signer.validator.act.LocalTimestampAuthority;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.security.Signature;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CmsTimestampEnhancerTest {

    private TestCertificateFactory.TestCredentials credentials;
    private LocalTimestampAuthority timestampAuthority;
    private byte[] samplePdf;

    @BeforeEach
    void setUp() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        credentials = TestCertificateFactory.generateRsa2048();
        timestampAuthority = LocalTimestampAuthority.generate();
        samplePdf = TestPdfFactory.createSamplePdf();
    }

    @Test
    void addsSignatureTimeStampTokenAttribute() throws Exception {
        byte[] cms = buildCms();

        byte[] enhanced = CmsTimestampEnhancer.enhance(cms, timestampAuthority);

        SignerInformation signer = singleSigner(new CMSSignedData(enhanced));
        assertNotNull(signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_messageDigest));
        assertNotNull(signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken));
    }

    private byte[] buildCms() throws Exception {
        PadesSignaturePreparer preparer = new PadesSignaturePreparer();
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());
        byte[] rawSignature = signDocumentHash(prepared.getDocumentHash());

        return CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                .rawSignature(rawSignature)
                .signerCertificate(credentials.certificate())
                .messageDigest(prepared.getDocumentHash())
                .digestAlgorithm(DigestAlgorithm.SHA256)
                .signingTime(new Date())
                .build());
    }

    private byte[] signDocumentHash(byte[] documentHash) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(credentials.keyPair().getPrivate());
        signature.update(documentHash);
        return signature.sign();
    }

    private static SignerInformation singleSigner(CMSSignedData signedData) {
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        Iterator<SignerInformation> iterator = signers.iterator();
        assertTrue(iterator.hasNext());
        return iterator.next();
    }
}
