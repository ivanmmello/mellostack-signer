package com.mellostack.signer.demo.session;

import org.icpbrasil.signer.model.Environment;

import java.time.Instant;

public final class SigningSession {

    private final String id;
    private final String providerId;
    private final Environment environment;
    private final byte[] pdfBytes;
    private final String fileName;
    private SigningSessionStatus status;
    private final Instant createdAt;

    private String reason;
    private String location;
    private boolean visibleSignature;
    private boolean timestamp;

    private String codeVerifier;
    private String accessToken;
    private byte[] signedPdfBytes;
    private String signerCertificateSubject;
    private Boolean validationValid;
    private String errorMessage;

    public SigningSession(
            String id,
            String providerId,
            Environment environment,
            byte[] pdfBytes,
            String fileName) {
        this.id = id;
        this.providerId = providerId;
        this.environment = environment;
        this.pdfBytes = pdfBytes;
        this.fileName = fileName;
        this.status = SigningSessionStatus.PREPARED;
        this.createdAt = Instant.now();
    }

    public String id() {
        return id;
    }

    public String providerId() {
        return providerId;
    }

    public Environment environment() {
        return environment;
    }

    public byte[] pdfBytes() {
        return pdfBytes;
    }

    public String fileName() {
        return fileName;
    }

    public SigningSessionStatus status() {
        return status;
    }

    public void setStatus(SigningSessionStatus status) {
        this.status = status;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public String reason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String location() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public boolean visibleSignature() {
        return visibleSignature;
    }

    public void setVisibleSignature(boolean visibleSignature) {
        this.visibleSignature = visibleSignature;
    }

    public boolean timestamp() {
        return timestamp;
    }

    public void setTimestamp(boolean timestamp) {
        this.timestamp = timestamp;
    }

    public String codeVerifier() {
        return codeVerifier;
    }

    public void setCodeVerifier(String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }

    public String accessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public byte[] signedPdfBytes() {
        return signedPdfBytes;
    }

    public void setSignedPdfBytes(byte[] signedPdfBytes) {
        this.signedPdfBytes = signedPdfBytes;
    }

    public String signerCertificateSubject() {
        return signerCertificateSubject;
    }

    public void setSignerCertificateSubject(String signerCertificateSubject) {
        this.signerCertificateSubject = signerCertificateSubject;
    }

    public Boolean validationValid() {
        return validationValid;
    }

    public void setValidationValid(Boolean validationValid) {
        this.validationValid = validationValid;
    }

    public String errorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
