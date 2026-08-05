package com.mellostack.signer.demo.service;

import com.mellostack.signer.demo.config.DemoProperties;
import com.mellostack.signer.demo.psc.DemoPscRegistry;
import com.mellostack.signer.demo.session.SigningSession;
import com.mellostack.signer.demo.session.SigningSessionStatus;
import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.validator.SignatureValidator;
import org.icpbrasil.signer.validator.act.ActClientConfig;
import org.icpbrasil.signer.validator.act.Rfc3161TimestampAuthority;
import org.icpbrasil.signer.validator.act.TimestampAuthority;
import org.icpbrasil.signer.validator.pades.PadesValidationResult;
import org.springframework.stereotype.Service;

@Service
public class DocumentSigningService {

    private final DemoProperties properties;
    private final DemoPscRegistry pscRegistry;
    private final SigningSessionService sessionService;

    public DocumentSigningService(
            DemoProperties properties,
            DemoPscRegistry pscRegistry,
            SigningSessionService sessionService) {
        this.properties = properties;
        this.pscRegistry = pscRegistry;
        this.sessionService = sessionService;
    }

    public SigningSession execute(String sessionId) {
        SigningSession session = sessionService.require(sessionId);
        if (session.accessToken() == null || session.accessToken().isBlank()) {
            throw new IllegalStateException("OAuth authorization required before signing");
        }

        try {
            DemoPscRegistry.DemoPscBundle bundle =
                    pscRegistry.bundleForSession(session.providerId(), session.environment());
            CloudSigner signer = new CloudSigner(bundle.provider(), timestampAuthority(session.timestamp()));

            SignatureOptions options = SignatureOptions.builder()
                    .withUserAccessToken(session.accessToken())
                    .withReason(session.reason())
                    .withLocation(session.location())
                    .withVisibleSignature(session.visibleSignature())
                    .withTimestamp(session.timestamp())
                    .build();

            byte[] signedPdf = signer.signPdf(session.pdfBytes(), options);
            PadesValidationResult validation = SignatureValidator.validateSignedPdf(signedPdf);

            session.setSignedPdfBytes(signedPdf);
            session.setValidationValid(validation.isValid() && validation.docIcpCompliant());
            session.setSignerCertificateSubject(
                    validation.signerCertificate() != null
                            ? validation.signerCertificate().getSubjectX500Principal().getName()
                            : null);
            session.setStatus(SigningSessionStatus.SIGNED);
            session.setErrorMessage(null);
            return session;
        } catch (RuntimeException ex) {
            sessionService.markFailed(session, ex.getMessage());
            throw ex;
        }
    }

    private TimestampAuthority timestampAuthority(boolean enabled) {
        if (!enabled) {
            return null;
        }
        String tsaUrl = properties.act().tsaUrl();
        if (tsaUrl == null || tsaUrl.isBlank()) {
            throw new IllegalStateException("ACT_TSA_URL must be configured when timestamp is enabled");
        }
        return new Rfc3161TimestampAuthority(ActClientConfig.of(tsaUrl.trim()));
    }
}
