package com.mellostack.signer.demo.web.dto;

public record SessionResponse(
        String sessionId,
        String provider,
        String environment,
        String status,
        String fileName,
        String reason,
        String location,
        boolean visibleSignature,
        boolean timestamp,
        boolean authorized,
        String signerCertificateSubject,
        Boolean validationValid,
        String errorMessage,
        String createdAt) {
}
