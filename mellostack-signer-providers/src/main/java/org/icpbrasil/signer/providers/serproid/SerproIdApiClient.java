package org.icpbrasil.signer.providers.serproid;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.csc.CscSignatureFormat;
import org.icpbrasil.signer.providers.csc.HashAlgorithmOid;
import org.icpbrasil.signer.providers.exception.PscException;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.iti.HashEncoding;
import org.icpbrasil.signer.providers.iti.ItiCloudPscApiClient;
import org.icpbrasil.signer.providers.iti.ItiCloudPscEndpoints;
import org.icpbrasil.signer.providers.iti.ItiCloudPscValidation;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Cliente REST SerproID: descoberta de certificado e assinatura RAW (hash Base64, SHA-256).
 */
public final class SerproIdApiClient implements SerproIdGateway {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SIGNATURE_ALIAS = "mellostack-signer";

    private final ItiCloudPscEndpoints endpoints;
    private final HttpClientFacade httpClient;
    private final ItiCloudPscApiClient discovery;

    public SerproIdApiClient(Environment environment, HttpClientFacade httpClient) {
        this.endpoints = new ItiCloudPscEndpoints(SerproIdEndpoints.baseUrl(environment));
        this.httpClient = httpClient;
        this.discovery = new ItiCloudPscApiClient(endpoints, httpClient, HashEncoding.BASE64, "SerproID");
    }

    @Override
    public List<SerproIdCertificate> discoverCertificates(String accessToken) {
        return discovery.discoverCertificates(accessToken).stream()
                .map(cert -> new SerproIdCertificate(cert.alias(), cert.certificate()))
                .toList();
    }

    @Override
    public byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm) {
        return signHashes(accessToken, certificateAlias, List.of(documentHash)).get(0);
    }

    @Override
    public List<byte[]> signHashes(
            String accessToken,
            String certificateAlias,
            List<byte[]> documentHashes) {
        ItiCloudPscValidation.validateAccessToken(accessToken);
        validateHashes(documentHashes);

        ObjectNode body = MAPPER.createObjectNode();
        ArrayNode hashes = body.putArray("hashes");
        for (int index = 0; index < documentHashes.size(); index++) {
            ObjectNode entry = hashes.addObject();
            entry.put("id", String.valueOf(index + 1));
            entry.put("alias", contentAlias(certificateAlias));
            entry.put("hash", EncodingUtils.toBase64(documentHashes.get(index)));
            entry.put("hash_algorithm", HashAlgorithmOid.SHA256);
            entry.put("signature_format", CscSignatureFormat.RAW.apiValue());
        }

        try {
            String response = httpClient.postJson(
                    endpoints.signatureUrl(),
                    SecureHttpClient.bearerHeaders(accessToken),
                    body.toString());
            return parseSignatures(response, documentHashes.size());
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscSigningException("Failed to sign hashes via SerproID", e);
        }
    }

    static void validateAccessToken(String accessToken) {
        ItiCloudPscValidation.validateAccessToken(accessToken);
    }

    static void validateCertificateAlias(String certificateAlias) {
        ItiCloudPscValidation.validateCertificateAlias(certificateAlias);
    }

    static void validateDocumentHash(byte[] documentHash) {
        if (documentHash == null || documentHash.length != 32) {
            throw new PscSigningException("SerproID accepts SHA-256 hashes only (32 bytes)");
        }
    }

    private static void validateHashes(List<byte[]> documentHashes) {
        if (documentHashes == null || documentHashes.isEmpty()) {
            throw new IllegalArgumentException("documentHashes must not be empty");
        }
        if (documentHashes.size() > SerproIdEndpoints.MAX_HASHES_PER_REQUEST) {
            throw new IllegalArgumentException(
                    "SerproID accepts at most " + SerproIdEndpoints.MAX_HASHES_PER_REQUEST + " hashes per request");
        }
        for (byte[] documentHash : documentHashes) {
            validateDocumentHash(documentHash);
        }
    }

    private static String contentAlias(String certificateAlias) {
        if (certificateAlias == null || certificateAlias.isBlank()) {
            return SIGNATURE_ALIAS;
        }
        return certificateAlias;
    }

    private static List<byte[]> parseSignatures(String responseJson, int expectedCount) throws Exception {
        JsonNode signatures = MAPPER.readTree(responseJson).path("signatures");
        if (!signatures.isArray() || signatures.isEmpty()) {
            throw new PscSigningException("SerproID signature response missing signatures");
        }
        List<JsonNode> ordered = new ArrayList<>();
        signatures.forEach(ordered::add);
        ordered.sort(Comparator.comparing(node -> node.path("id").asText("")));
        if (ordered.size() != expectedCount) {
            throw new PscSigningException("SerproID returned "
                    + ordered.size() + " signatures, expected " + expectedCount);
        }
        List<byte[]> decoded = new ArrayList<>(expectedCount);
        for (JsonNode entry : ordered) {
            String raw = entry.path("raw_signature").asText("");
            if (raw.isBlank()) {
                throw new PscSigningException("SerproID signature response missing raw_signature");
            }
            byte[] signature = EncodingUtils.fromBase64(raw);
            if (signature.length == 0) {
                throw new PscSigningException("SerproID returned an empty raw signature");
            }
            decoded.add(signature);
        }
        return List.copyOf(decoded);
    }

    public record SerproIdCertificate(String alias, java.security.cert.X509Certificate certificate) {
    }
}
