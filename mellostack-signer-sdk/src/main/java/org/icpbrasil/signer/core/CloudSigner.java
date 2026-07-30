package org.icpbrasil.signer.core;

import org.icpbrasil.signer.core.cms.CmsAssemblyRequest;
import org.icpbrasil.signer.core.cms.CmsEnvelopeAssembler;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignatureInjector;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.icpbrasil.signer.validator.act.TimestampAuthority;
import org.icpbrasil.signer.validator.cms.CmsTimestampEnhancer;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Fachada principal para assinatura digital qualificada em nuvem (PAdES / Cadeia V12).
 */
public final class CloudSigner {

    private final PSCProvider provider;
    private final PadesSignaturePreparer preparer;
    private final PadesSignatureInjector injector;
    private final TimestampAuthority timestampAuthority;

    public CloudSigner(PSCProvider provider) {
        this(provider, null);
    }

    /**
     * @param timestampAuthority ACT configurável pela aplicação host (por tenant/ambiente).
     *                           Obrigatória quando {@link SignatureOptions#isTimestamp()} for {@code true}.
     */
    public CloudSigner(PSCProvider provider, TimestampAuthority timestampAuthority) {
        this(provider, timestampAuthority, new PadesSignaturePreparer(), new PadesSignatureInjector());
    }

    CloudSigner(
            PSCProvider provider,
            TimestampAuthority timestampAuthority,
            PadesSignaturePreparer preparer,
            PadesSignatureInjector injector) {
        if (provider == null) {
            throw new IllegalArgumentException("PSCProvider must not be null");
        }
        if (preparer == null) {
            throw new IllegalArgumentException("preparer must not be null");
        }
        if (injector == null) {
            throw new IllegalArgumentException("injector must not be null");
        }
        this.provider = provider;
        this.timestampAuthority = timestampAuthority;
        this.preparer = preparer;
        this.injector = injector;
    }

    /**
     * Assina um documento PDF utilizando o PSC configurado.
     *
     * @param pdfBytes bytes do PDF original
     * @param options  opções de assinatura (token OAuth2, reason, location, etc.)
     * @return bytes do PDF assinado com conformidade ICP-Brasil V12
     */
    public byte[] signPdf(byte[] pdfBytes, SignatureOptions options) {
        if (pdfBytes == null || pdfBytes.length == 0) {
            throw new IllegalArgumentException("pdfBytes must not be empty");
        }
        if (options == null) {
            throw new IllegalArgumentException("SignatureOptions must not be null");
        }
        if (options.getUserAccessToken() == null || options.getUserAccessToken().isBlank()) {
            throw new IllegalArgumentException("userAccessToken must not be empty");
        }
        if (options.isTimestamp() && timestampAuthority == null) {
            throw new IllegalStateException(
                    "TimestampAuthority must be configured on CloudSigner when withTimestamp(true)");
        }

        try {
            PadesPrepareOptions prepareOptions = PadesPrepareOptions.from(options);
            PreparedSignature prepared = preparer.prepare(pdfBytes, prepareOptions);

            String accessToken = options.getUserAccessToken();
            byte[] rawSignature = provider.signHash(prepared.getDocumentHash(), accessToken);
            if (rawSignature == null || rawSignature.length == 0) {
                throw new IllegalStateException("PSC returned an empty signature");
            }

            X509Certificate signerCertificate = provider.getSignerCertificate(accessToken);
            if (signerCertificate == null) {
                throw new IllegalStateException("PSC did not return a signer certificate");
            }

            byte[] cms = CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                    .rawSignature(rawSignature)
                    .signerCertificate(signerCertificate)
                    .certificateChain(provider.getCertificateChain(accessToken))
                    .messageDigest(prepared.getDocumentHash())
                    .digestAlgorithm(prepared.getDigestAlgorithm())
                    .signingTime(new Date())
                    .build());

            if (options.isTimestamp()) {
                cms = CmsTimestampEnhancer.enhance(cms, timestampAuthority);
            }

            return injector.inject(prepared, cms);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare or inject PDF signature", e);
        } catch (CMSException | CertificateEncodingException | OperatorCreationException
                 | org.bouncycastle.tsp.TSPException e) {
            throw new IllegalStateException("Failed to assemble CMS envelope", e);
        }
    }

    public PSCProvider getProvider() {
        return provider;
    }

    public TimestampAuthority getTimestampAuthority() {
        return timestampAuthority;
    }
}
