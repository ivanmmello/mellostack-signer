package com.mellostack.signer.demo.service;

import com.mellostack.signer.demo.config.DemoProperties;
import com.mellostack.signer.demo.psc.DemoPscRegistry;
import com.mellostack.signer.demo.session.SigningSession;
import com.mellostack.signer.demo.session.SigningSessionStatus;
import com.mellostack.signer.demo.session.SigningSessionStore;
import com.mellostack.signer.demo.web.dto.PrepareSignRequest;
import com.mellostack.signer.demo.web.dto.SessionResponse;
import com.mellostack.signer.demo.web.dto.UpdateOptionsRequest;
import org.icpbrasil.signer.model.Environment;
import org.springframework.stereotype.Service;

@Service
public class SigningSessionService {

    private final SigningSessionStore store;
    private final DemoPscRegistry pscRegistry;

    public SigningSessionService(SigningSessionStore store, DemoPscRegistry pscRegistry) {
        this.store = store;
        this.pscRegistry = pscRegistry;
    }

    public SigningSession prepare(byte[] pdfBytes, String fileName, PrepareSignRequest request) {
        Environment environment = parseEnvironment(request.environment());
        DemoPscRegistry.DemoPscBundle bundle = pscRegistry.bundleForSession(request.provider(), environment);

        SigningSession session = store.create(bundle.providerId(), bundle.environment(), pdfBytes, fileName);
        session.setReason(defaultValue(request.reason(), "Assinatura digital ICP-Brasil"));
        session.setLocation(defaultValue(request.location(), "Brasil"));
        session.setVisibleSignature(request.visibleSignature());
        session.setTimestamp(request.timestamp());
        return session;
    }

    public SessionResponse toResponse(SigningSession session) {
        return new SessionResponse(
                session.id(),
                session.providerId(),
                session.environment().name(),
                session.status().name(),
                session.fileName(),
                session.reason(),
                session.location(),
                session.visibleSignature(),
                session.timestamp(),
                session.accessToken() != null,
                session.signerCertificateSubject(),
                session.validationValid(),
                session.errorMessage(),
                session.createdAt().toString()
        );
    }

    public SigningSession require(String sessionId) {
        return store.require(sessionId);
    }

    public SigningSession updateOptions(String sessionId, UpdateOptionsRequest request) {
        SigningSession session = require(sessionId);
        session.setReason(defaultValue(request.reason(), session.reason()));
        session.setLocation(defaultValue(request.location(), session.location()));
        session.setVisibleSignature(request.visibleSignature());
        session.setTimestamp(request.timestamp());
        return session;
    }

    private static Environment parseEnvironment(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return switch (raw.trim().toLowerCase()) {
            case "production", "prod" -> Environment.PRODUCTION;
            default -> Environment.HOMOLOGATION;
        };
    }

    public void markFailed(SigningSession session, String message) {
        session.setStatus(SigningSessionStatus.FAILED);
        session.setErrorMessage(message);
    }

    private static String defaultValue(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value.trim();
    }
}
