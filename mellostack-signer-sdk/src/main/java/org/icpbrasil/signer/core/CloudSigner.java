package org.icpbrasil.signer.core;

import org.icpbrasil.signer.core.cms.CmsAssemblyRequest;
import org.icpbrasil.signer.core.cms.CmsEnvelopeAssembler;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignatureInjector;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.icpbrasil.signer.core.pdf.PreparedSignature;
import org.icpbrasil.signer.model.BatchSigningLimits;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.icpbrasil.signer.validator.act.TimestampAuthority;
import org.icpbrasil.signer.validator.cms.CmsTimestampEnhancer;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Fachada principal para assinatura digital qualificada em nuvem (PAdES / Cadeia V12).
 */
public final class CloudSigner {

    private final PSCProvider provider;
    private final PadesSignaturePreparer preparer;
    private final PadesSignatureInjector injector;
    private final TimestampAuthority timestampAuthority;

    /**
     * @param provider driver PSC configurado (Bird ID, Remote ID, etc.)
     */
    public CloudSigner(PSCProvider provider) {
        this(provider, null);
    }

    /**
     * @param provider           driver PSC configurado
     * @param timestampAuthority ACT configurável pela aplicação host (por tenant/ambiente).
     *                           Obrigatória quando {@link SignatureOptions#isTimestamp()} for {@code true}
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
        List<byte[]> signed = signPdfBatch(List.of(pdfBytes), options);
        return signed.get(0);
    }

    /**
     * Assina múltiplos PDFs com uma única autorização PSC quando o driver suporta lote
     * ({@link PSCProvider#supportsBatchSigning()}).
     *
     * @param pdfBytesList PDFs originais, na ordem desejada de saída
     * @param options      opções compartilhadas (token OAuth2, reason, location, etc.)
     * @return PDFs assinados na mesma ordem de {@code pdfBytesList}
     */
    public List<byte[]> signPdfBatch(List<byte[]> pdfBytesList, SignatureOptions options) {
        validateBatchInput(pdfBytesList, options);
        if (options.isTimestamp() && timestampAuthority == null) {
            throw new IllegalStateException(
                    "TimestampAuthority must be configured on CloudSigner when withTimestamp(true)");
        }

        try {
            PadesPrepareOptions prepareOptions = PadesPrepareOptions.from(options);
            List<PreparedSignature> preparedList = new ArrayList<>(pdfBytesList.size());
            for (byte[] pdfBytes : pdfBytesList) {
                preparedList.add(preparer.prepare(pdfBytes, prepareOptions));
            }

            String accessToken = options.getUserAccessToken();
            List<byte[]> documentHashes = preparedList.stream()
                    .map(PreparedSignature::getDocumentHash)
                    .toList();

            boolean preparedCms = provider.returnsPreparedCms();
            List<byte[]> rawSignatures = provider.signHashes(documentHashes, accessToken);
            if (rawSignatures.size() != preparedList.size()) {
                throw new IllegalStateException("PSC returned "
                        + rawSignatures.size() + " signatures for " + preparedList.size() + " documents");
            }

            X509Certificate signerCertificate = provider.getSignerCertificate(accessToken);
            if (signerCertificate == null) {
                throw new IllegalStateException("PSC did not return a signer certificate");
            }

            List<X509Certificate> certificateChain = provider.getCertificateChain(accessToken);
            List<byte[]> signedPdfs = new ArrayList<>(preparedList.size());
            for (int index = 0; index < preparedList.size(); index++) {
                PreparedSignature prepared = preparedList.get(index);
                byte[] rawSignature = rawSignatures.get(index);
                if (rawSignature == null || rawSignature.length == 0) {
                    throw new IllegalStateException("PSC returned an empty signature at index " + index);
                }

                byte[] cms = preparedCms
                        ? rawSignature
                        : CmsEnvelopeAssembler.assembleDetached(CmsAssemblyRequest.builder()
                                .rawSignature(rawSignature)
                                .signerCertificate(signerCertificate)
                                .certificateChain(certificateChain)
                                .messageDigest(prepared.getDocumentHash())
                                .digestAlgorithm(prepared.getDigestAlgorithm())
                                .signingTime(new Date())
                                .build());

                if (options.isTimestamp()) {
                    cms = CmsTimestampEnhancer.enhance(cms, timestampAuthority);
                }

                signedPdfs.add(injector.inject(prepared, cms));
            }
            return signedPdfs;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare or inject PDF signature", e);
        } catch (CMSException | CertificateEncodingException | OperatorCreationException
                 | org.bouncycastle.tsp.TSPException e) {
            throw new IllegalStateException("Failed to assemble CMS envelope", e);
        }
    }

    private static void validateBatchInput(List<byte[]> pdfBytesList, SignatureOptions options) {
        Objects.requireNonNull(pdfBytesList, "pdfBytesList");
        if (pdfBytesList.isEmpty()) {
            throw new IllegalArgumentException("pdfBytesList must not be empty");
        }
        if (pdfBytesList.size() > BatchSigningLimits.MAX_DOCUMENTS) {
            throw new IllegalArgumentException(
                    "pdfBytesList exceeds maximum batch size of " + BatchSigningLimits.MAX_DOCUMENTS);
        }
        for (int index = 0; index < pdfBytesList.size(); index++) {
            byte[] pdfBytes = pdfBytesList.get(index);
            if (pdfBytes == null || pdfBytes.length == 0) {
                throw new IllegalArgumentException("pdfBytes at index " + index + " must not be empty");
            }
        }
        if (options == null) {
            throw new IllegalArgumentException("SignatureOptions must not be null");
        }
        if (options.getUserAccessToken() == null || options.getUserAccessToken().isBlank()) {
            throw new IllegalArgumentException("userAccessToken must not be empty");
        }
    }

    /** @return driver PSC associado a esta instância */
    public PSCProvider getProvider() {
        return provider;
    }

    /** @return ACT configurada, ou {@code null} quando assinatura sem carimbo do tempo */
    public TimestampAuthority getTimestampAuthority() {
        return timestampAuthority;
    }
}
