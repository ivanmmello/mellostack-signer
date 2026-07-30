package org.icpbrasil.signer.providers.vidaas;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.iti.HashEncoding;
import org.icpbrasil.signer.providers.iti.ItiCloudPscApiClient;
import org.icpbrasil.signer.providers.iti.ItiCloudPscEndpoints;
import org.icpbrasil.signer.providers.iti.ItiCloudPscValidation;

import java.util.List;

/**
 * Cliente REST VIDaaS (Valid) para descoberta de certificado e assinatura de hash (RAW).
 * <p>
 * O hash é enviado em Base64, conforme manual de integração Valid.
 */
public final class VidaasApiClient implements VidaasGateway {

    private final ItiCloudPscApiClient delegate;

    public VidaasApiClient(Environment environment, HttpClientFacade httpClient) {
        ItiCloudPscEndpoints endpoints = new ItiCloudPscEndpoints(VidaasEndpoints.baseUrl(environment));
        this.delegate = new ItiCloudPscApiClient(endpoints, httpClient, HashEncoding.BASE64, "VIDaaS");
    }

    VidaasApiClient(ItiCloudPscApiClient delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<VidaasCertificate> discoverCertificates(String accessToken) {
        return delegate.discoverCertificates(accessToken).stream()
                .map(cert -> new VidaasCertificate(cert.alias(), cert.certificate()))
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

    public record VidaasCertificate(String alias, java.security.cert.X509Certificate certificate) {
    }
}
