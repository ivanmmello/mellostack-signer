package org.icpbrasil.signer.providers.birdid;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.iti.HashEncoding;
import org.icpbrasil.signer.providers.iti.ItiCloudPscApiClient;
import org.icpbrasil.signer.providers.iti.ItiCloudPscEndpoints;
import org.icpbrasil.signer.providers.iti.ItiCloudPscValidation;

import java.util.List;

/**
 * Cliente REST Bird ID para descoberta de certificado e assinatura de hash (RAW).
 */
public final class BirdIdApiClient implements BirdIdGateway {

    private final ItiCloudPscApiClient delegate;

    public BirdIdApiClient(Environment environment, HttpClientFacade httpClient) {
        ItiCloudPscEndpoints endpoints = new ItiCloudPscEndpoints(BirdIdEndpoints.baseUrl(environment));
        this.delegate = new ItiCloudPscApiClient(endpoints, httpClient, HashEncoding.HEX, "Bird ID");
    }

    BirdIdApiClient(ItiCloudPscApiClient delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<BirdIdCertificate> discoverCertificates(String accessToken) {
        return delegate.discoverCertificates(accessToken).stream()
                .map(cert -> new BirdIdCertificate(cert.alias(), cert.certificate()))
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

    public record BirdIdCertificate(String alias, java.security.cert.X509Certificate certificate) {
    }
}
