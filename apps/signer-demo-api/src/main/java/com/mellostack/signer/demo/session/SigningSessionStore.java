package com.mellostack.signer.demo.session;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SigningSessionStore {

    private final Map<String, SigningSession> sessions = new ConcurrentHashMap<>();

    public SigningSession create(String providerId, org.icpbrasil.signer.model.Environment environment,
                                 byte[] pdfBytes, String fileName) {
        String id = UUID.randomUUID().toString();
        SigningSession session = new SigningSession(id, providerId, environment, pdfBytes, fileName);
        sessions.put(id, session);
        return session;
    }

    public SigningSession require(String sessionId) {
        return find(sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found: " + sessionId));
    }

    public Optional<SigningSession> find(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.get(sessionId));
    }
}
