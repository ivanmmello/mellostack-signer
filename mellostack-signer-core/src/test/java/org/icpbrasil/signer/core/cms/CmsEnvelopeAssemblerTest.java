package org.icpbrasil.signer.core.cms;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.icpbrasil.signer.core.crypto.DocumentDigestCalculator;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignatureInjector;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PdfIntegrityValidator;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.core.pdf.TestPdfFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.security.Signature;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CmsEnvelopeAssemblerTest {

    private byte[] samplePdf;
    private PadesSignaturePreparer preparer;
    private TestCertificateFactory.TestCredentials credentials;

    @BeforeEach
    void setUp() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        samplePdf = TestPdfFactory.createSamplePdf();
        preparer = new PadesSignaturePreparer();
        credentials = TestCertificateFactory.generateRsa2048();
    }

    @Test
    void assemblesDetachedCmsWithRequiredSignedAttributes() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());
        byte[] rawSignature = signDocumentHash(prepared.getDocumentHash());

        byte[] cms = CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                .rawSignature(rawSignature)
                .signerCertificate(credentials.certificate())
                .messageDigest(prepared.getDocumentHash())
                .digestAlgorithm(DigestAlgorithm.SHA256)
                .signingTime(new Date())
                .build());

        CMSSignedData signedData = new CMSSignedData(cms);
        SignerInformation signer = singleSigner(signedData);

        assertNotNull(signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_contentType));
        assertNotNull(signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_messageDigest));
        assertNotNull(signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_signingTime));
        assertNotNull(signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2));
        assertEquals(1, signedData.getCertificates().getMatches(null).size());
    }

    @Test
    void includesCertificateChainInCms() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());
        byte[] rawSignature = signDocumentHash(prepared.getDocumentHash());

        TestCertificateFactory.TestCredentials intermediate = TestCertificateFactory.generateRsa2048();

        byte[] cms = CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                .rawSignature(rawSignature)
                .signerCertificate(credentials.certificate())
                .certificateChain(java.util.List.of(intermediate.certificate()))
                .messageDigest(prepared.getDocumentHash())
                .digestAlgorithm(DigestAlgorithm.SHA256)
                .signingTime(new Date())
                .build());

        CMSSignedData signedData = new CMSSignedData(cms);
        assertEquals(2, signedData.getCertificates().getMatches(null).size());
    }

    @Test
    void cmsCanBeInjectedIntoPreparedPdf() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());
        byte[] rawSignature = signDocumentHash(prepared.getDocumentHash());

        byte[] cms = CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                .rawSignature(rawSignature)
                .signerCertificate(credentials.certificate())
                .messageDigest(prepared.getDocumentHash())
                .digestAlgorithm(DigestAlgorithm.SHA256)
                .signingTime(new Date())
                .build());

        byte[] signedPdf = new PadesSignatureInjector().inject(prepared, cms);

        assertTrue(PdfIntegrityValidator.isReadablePdf(signedPdf));
        assertDoesNotThrow(() -> PdfIntegrityValidator.validateAfterInjection(signedPdf));
    }

    @Test
    void messageDigestAttributeMatchesDocumentHash() throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder()
                .digestAlgorithm(DigestAlgorithm.SHA384)
                .build());

        byte[] validatedHash = DocumentDigestCalculator.computeSha384(
                prepared.getPreparedPdf(),
                prepared.getByteRange()
        );

        byte[] rawSignature = signDocumentHashSha384(validatedHash);

        byte[] cms = CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                .rawSignature(rawSignature)
                .signerCertificate(credentials.certificate())
                .messageDigest(validatedHash)
                .digestAlgorithm(DigestAlgorithm.SHA384)
                .signingTime(new Date())
                .build());

        CMSSignedData signedData = new CMSSignedData(cms);
        SignerInformation signer = singleSigner(signedData);
        assertNotNull(signer.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_messageDigest));
    }

    private byte[] signDocumentHash(byte[] documentHash) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(credentials.keyPair().getPrivate());
        signature.update(documentHash);
        return signature.sign();
    }

    private byte[] signDocumentHashSha384(byte[] documentHash) throws Exception {
        Signature signature = Signature.getInstance("SHA384withRSA", "BC");
        signature.initSign(credentials.keyPair().getPrivate());
        signature.update(documentHash);
        return signature.sign();
    }

    private static SignerInformation singleSigner(CMSSignedData signedData) {
        SignerInformationStore signers = signedData.getSignerInfos();
        Collection<SignerInformation> matches = signers.getSigners();
        Iterator<SignerInformation> iterator = matches.iterator();
        assertTrue(iterator.hasNext());
        return iterator.next();
    }
}
