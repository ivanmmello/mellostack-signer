package org.icpbrasil.signer.validator.pades;

import org.icpbrasil.signer.core.cms.CmsAssemblyRequest;
import org.icpbrasil.signer.core.cms.CmsEnvelopeAssembler;
import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignatureInjector;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.core.pdf.TestPdfFactory;
import org.icpbrasil.signer.validator.SignatureValidator;
import org.icpbrasil.signer.validator.act.LocalTimestampAuthority;
import org.icpbrasil.signer.validator.cms.CmsTimestampEnhancer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Signature;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PadesSignatureVerifierTest {

    private byte[] samplePdf;
    private TestCertificateFactory.TestCredentials credentials;
    private PadesSignaturePreparer preparer;

    @BeforeEach
    void setUp() throws Exception {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        samplePdf = TestPdfFactory.createSamplePdf();
        credentials = TestCertificateFactory.generateRsa2048();
        preparer = new PadesSignaturePreparer();
    }

    @Test
    void verifiesSignedPdfEndToEnd() throws Exception {
        byte[] signedPdf = signSamplePdf(false);

        PadesValidationResult result = PadesSignatureVerifier.verify(signedPdf);

        assertTrue(result.signatureValid(), "signatureValid policy=" + result.policyResult().violations());
        assertTrue(result.docIcpCompliant(), "docIcp violations=" + result.policyResult().violations());
        assertTrue(result.isValid());
        assertTrue(SignatureValidator.isSignedPdfValid(signedPdf));
    }

    @Test
    void detectsTimestampWhenPresent() throws Exception {
        byte[] signedPdf = signSamplePdf(true);

        PadesValidationResult result = PadesSignatureVerifier.verify(signedPdf);

        assertTrue(result.isValid());
        assertTrue(result.hasTimestamp());
    }

    @Test
    void rejectsEmptyPdf() {
        assertFalse(PadesSignatureVerifier.isValid(new byte[0]));
    }

    private byte[] signSamplePdf(boolean withTimestamp) throws Exception {
        PreparedSignature prepared = preparer.prepare(samplePdf, PadesPrepareOptions.builder().build());
        byte[] rawSignature = signHash(prepared.getDocumentHash());

        byte[] cms = CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                .rawSignature(rawSignature)
                .signerCertificate(credentials.certificate())
                .messageDigest(prepared.getDocumentHash())
                .digestAlgorithm(prepared.getDigestAlgorithm())
                .signingTime(new Date())
                .build());

        if (withTimestamp) {
            cms = CmsTimestampEnhancer.enhance(cms, LocalTimestampAuthority.generate());
        }

        return new PadesSignatureInjector().inject(prepared, cms);
    }

    private byte[] signHash(byte[] documentHash) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(credentials.keyPair().getPrivate());
        signature.update(documentHash);
        return signature.sign();
    }
}
