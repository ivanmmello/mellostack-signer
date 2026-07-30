package org.icpbrasil.signer.providers.iti;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.providers.csc.CscSignatureFormat;
import org.icpbrasil.signer.providers.csc.HashAlgorithmOid;
import org.icpbrasil.signer.providers.exception.PscException;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.http.SecureHttpClient;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Cliente REST genérico para PSCs em nuvem no padrão ITI ({@code /v0/oauth/*}).
 */
public final class ItiCloudPscApiClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SIGNATURE_HISTORY_ALIAS = "mellostack-signer";

    private final ItiCloudPscEndpoints endpoints;
    private final HttpClientFacade httpClient;
    private final HashEncoding hashEncoding;
    private final String providerLabel;

    public ItiCloudPscApiClient(
            ItiCloudPscEndpoints endpoints,
            HttpClientFacade httpClient,
            HashEncoding hashEncoding,
            String providerLabel) {
        this.endpoints = Objects.requireNonNull(endpoints, "endpoints");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.hashEncoding = Objects.requireNonNull(hashEncoding, "hashEncoding");
        this.providerLabel = Objects.requireNonNull(providerLabel, "providerLabel");
        if (providerLabel.isBlank()) {
            throw new IllegalArgumentException("providerLabel must not be blank");
        }
    }

    public List<DiscoveredCertificate> discoverCertificates(String accessToken) {
        ItiCloudPscValidation.validateAccessToken(accessToken);
        String response = httpClient.get(
                endpoints.certificateDiscoveryUrl(),
                SecureHttpClient.bearerHeaders(accessToken)
        );
        return parseCertificates(response);
    }

    public byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm) {
        ItiCloudPscValidation.validateAccessToken(accessToken);
        ItiCloudPscValidation.validateCertificateAlias(certificateAlias);
        ItiCloudPscValidation.validateDocumentHash(documentHash);

        Map<String, Object> hashEntry = new LinkedHashMap<>();
        hashEntry.put("id", "1");
        hashEntry.put("alias", SIGNATURE_HISTORY_ALIAS);
        hashEntry.put("hash", encodeHash(documentHash));
        hashEntry.put("hash_algorithm", HashAlgorithmOid.forDigest(digestAlgorithm));
        hashEntry.put("signature_format", CscSignatureFormat.RAW.apiValue());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("certificate_alias", certificateAlias);
        body.put("hashes", List.of(hashEntry));

        try {
            String json = MAPPER.writeValueAsString(body);
            String response = httpClient.postJson(
                    endpoints.signatureUrl(),
                    SecureHttpClient.bearerHeaders(accessToken),
                    json
            );
            return parseRawSignature(response);
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscSigningException("Failed to sign hash via " + providerLabel, e);
        }
    }

    private String encodeHash(byte[] documentHash) {
        return switch (hashEncoding) {
            case HEX -> EncodingUtils.toHex(documentHash);
            case BASE64 -> EncodingUtils.toBase64(documentHash);
        };
    }

    private List<DiscoveredCertificate> parseCertificates(String responseJson) {
        try {
            ItiCloudPscCertificateDiscoveryResponse parsed =
                    MAPPER.readValue(responseJson, ItiCloudPscCertificateDiscoveryResponse.class);
            if (!isSuccessStatus(parsed.status())) {
                throw new PscSigningException(providerLabel + " certificate discovery failed");
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return parsed.certificates().stream()
                    .map(entry -> toCertificate(factory, entry))
                    .toList();
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscSigningException(
                    "Failed to parse " + providerLabel + " certificate discovery response", e);
        }
    }

    private DiscoveredCertificate toCertificate(
            CertificateFactory factory,
            ItiCloudPscCertificateDiscoveryResponse.CertificateEntry entry) {
        if (entry.alias() == null || entry.alias().isBlank()) {
            throw new PscSigningException(providerLabel + " certificate entry missing alias");
        }
        if (entry.certificate() == null || entry.certificate().isBlank()) {
            throw new PscSigningException(providerLabel + " certificate entry missing PEM data");
        }
        try {
            byte[] pemBytes = entry.certificate().getBytes(StandardCharsets.US_ASCII);
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(pemBytes));
            return new DiscoveredCertificate(entry.alias(), certificate);
        } catch (CertificateException e) {
            throw new PscSigningException("Invalid certificate returned by " + providerLabel, e);
        }
    }

    private byte[] parseRawSignature(String responseJson) throws Exception {
        ItiCloudPscSignatureResponse parsed = MAPPER.readValue(responseJson, ItiCloudPscSignatureResponse.class);
        if (!parsed.signatures().isEmpty()) {
            return decodeRawSignature(parsed.signatures().get(0).rawSignature());
        }

        ItiCloudPscFlatSignatureResponse flat =
                MAPPER.readValue(responseJson, ItiCloudPscFlatSignatureResponse.class);
        if (!isSuccessStatus(flat.status())) {
            throw new PscSigningException(providerLabel + " signature request failed");
        }
        return decodeRawSignature(flat.rawSignature());
    }

    private byte[] decodeRawSignature(String rawSignature) {
        if (rawSignature == null || rawSignature.isBlank()) {
            throw new PscSigningException(providerLabel + " signature response missing raw_signature");
        }
        byte[] decoded = EncodingUtils.fromBase64(rawSignature);
        if (decoded.length == 0) {
            throw new PscSigningException(providerLabel + " returned an empty raw signature");
        }
        return decoded;
    }

    private static boolean isSuccessStatus(String status) {
        return "S".equalsIgnoreCase(status) || "success".equalsIgnoreCase(status);
    }

    public record DiscoveredCertificate(String alias, X509Certificate certificate) {
    }
}
