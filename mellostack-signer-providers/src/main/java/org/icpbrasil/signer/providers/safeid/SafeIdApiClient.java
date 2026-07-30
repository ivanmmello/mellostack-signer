package org.icpbrasil.signer.providers.safeid;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.iti.HashEncoding;
import org.icpbrasil.signer.providers.iti.ItiCloudPscApiClient;
import org.icpbrasil.signer.providers.iti.ItiCloudPscEndpoints;
import org.icpbrasil.signer.providers.iti.ItiCloudPscValidation;

import java.util.List;

/**
 * Cliente REST SafeID (Safeweb) para descoberta de certificado e assinatura de hash (RAW).
 * <p>
 * Hash enviado em hexadecimal, conforme requisitos operacionais do PSC Safeweb.
 */
public final class SafeIdApiClient implements SafeIdGateway {

    private final ItiCloudPscApiClient delegate;

    public SafeIdApiClient(Environment environment, HttpClientFacade httpClient) {
        ItiCloudPscEndpoints endpoints = new ItiCloudPscEndpoints(SafeIdEndpoints.baseUrl(environment));
        this.delegate = new ItiCloudPscApiClient(endpoints, httpClient, HashEncoding.HEX, "SafeID");
    }

    SafeIdApiClient(ItiCloudPscApiClient delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<SafeIdCertificate> discoverCertificates(String accessToken) {
        return delegate.discoverCertificates(accessToken).stream()
                .map(cert -> new SafeIdCertificate(cert.alias(), cert.certificate()))
                .toList();
    }

    @Override
    public byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm) {
        return delegate.signHash(accessToken, certificateAlias, documentHash, digestAlgorithm);
    }

    static void validateAccessToken(String accessToken) {
        ItiCloudPscValidation.validateAccessToken(accessToken);
    }

    static void validateCertificateAlias(String certificateAlias) {
        ItiCloudPscValidation.validateCertificateAlias(certificateAlias);
    }

    static void validateDocumentHash(byte[] documentHash) {
        ItiCloudPscValidation.validateDocumentHash(documentHash);
    }

    public record SafeIdCertificate(String alias, java.security.cert.X509Certificate certificate) {
    }
}
