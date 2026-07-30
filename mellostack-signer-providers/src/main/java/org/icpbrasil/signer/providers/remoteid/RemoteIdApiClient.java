package org.icpbrasil.signer.providers.remoteid;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.iti.HashEncoding;
import org.icpbrasil.signer.providers.iti.ItiCloudPscApiClient;
import org.icpbrasil.signer.providers.iti.ItiCloudPscEndpoints;
import org.icpbrasil.signer.providers.iti.ItiCloudPscValidation;

import java.util.List;

/**
 * Cliente REST Certisign Remote ID para descoberta de certificado e assinatura de hash (RAW).
 * <p>
 * A URL base da API é fornecida pelo integrador Certisign — não há endpoints públicos fixos.
 */
public final class RemoteIdApiClient implements RemoteIdGateway {

    private final ItiCloudPscApiClient delegate;

    public RemoteIdApiClient(String apiBaseUrl, HttpClientFacade httpClient) {
        this(apiBaseUrl, httpClient, HashEncoding.HEX);
    }

    public RemoteIdApiClient(String apiBaseUrl, HttpClientFacade httpClient, HashEncoding hashEncoding) {
        ItiCloudPscEndpoints endpoints = new ItiCloudPscEndpoints(apiBaseUrl);
        this.delegate = new ItiCloudPscApiClient(endpoints, httpClient, hashEncoding, "Remote ID");
    }

    RemoteIdApiClient(ItiCloudPscApiClient delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<RemoteIdCertificate> discoverCertificates(String accessToken) {
        return delegate.discoverCertificates(accessToken).stream()
                .map(cert -> new RemoteIdCertificate(cert.alias(), cert.certificate()))
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

    static void validateApiBaseUrl(String apiBaseUrl) {
        if (apiBaseUrl == null || apiBaseUrl.isBlank()) {
            throw new IllegalArgumentException("apiBaseUrl must not be blank");
        }
        if (apiBaseUrl.length() > 2048) {
            throw new IllegalArgumentException("apiBaseUrl exceeds maximum allowed length");
        }
    }

    public record RemoteIdCertificate(String alias, java.security.cert.X509Certificate certificate) {
    }
}
