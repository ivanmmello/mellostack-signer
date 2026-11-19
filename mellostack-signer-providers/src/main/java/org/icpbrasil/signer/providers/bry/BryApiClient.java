package org.icpbrasil.signer.providers.bry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.exception.PscAuthenticationException;
import org.icpbrasil.signer.providers.exception.PscException;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.oauth.OAuth2TokenResponse;

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Cliente HTTP da Integra Bry: JWT da aplicação, link do PSC, certificado e CMS por hash.
 */
final class BryApiClient implements BryGateway {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EXPIRY_SKEW_SECONDS = 30;

    private final Environment environment;
    private final String clientId;
    private final String clientSecret;
    private final String pscServiceUrl;
    private final HttpClientFacade httpClient;

    private String cachedApplicationJwt;
    private Instant applicationJwtExpiresAt = Instant.EPOCH;

    BryApiClient(
            Environment environment,
            String clientId,
            String clientSecret,
            String pscServiceUrl,
            HttpClientFacade httpClient) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.clientSecret = Objects.requireNonNull(clientSecret, "clientSecret");
        this.pscServiceUrl = Objects.requireNonNull(pscServiceUrl, "pscServiceUrl");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    @Override
    public BryAuthorizationLink createAuthorizationLink(BryAuthorizationRequest request) {
        Objects.requireNonNull(request, "request");
        ObjectNode body = MAPPER.createObjectNode();
        body.put("pscName", request.psc().apiName());
        body.put("redirectUri", request.redirectUri());
        body.put("state", request.state());
        body.put("scope", request.scope().apiValue());
        if (request.lifetimeSeconds() != null) {
            body.put("lifetime", request.lifetimeSeconds());
        }
        if (request.numberOfDocuments() != null) {
            body.put("numberOfDocuments", request.numberOfDocuments());
        }
        if (request.cpf() != null && !request.cpf().isBlank()) {
            body.put("cpf", request.cpf());
        }
        if (request.cnpj() != null && !request.cnpj().isBlank()) {
            body.put("cnpj", request.cnpj());
        }

        String response = httpClient.postJson(
                BryEndpoints.pscLinkUrl(environment),
                applicationHeaders(),
                body.toString());
        return parseLink(response);
    }

    @Override
    public X509Certificate fetchCertificate(String signerToken) {
        validateSignerToken(signerToken);
        Map<String, String> headers = applicationHeaders();
        headers.put("X-API-KEY", signerToken);
        String response = httpClient.get(BryEndpoints.certificateUrl(environment), headers);
        return parseCertificate(response);
    }

    @Override
    public List<byte[]> signCmsHashes(String signerToken, List<byte[]> documentHashes) {
        validateSignerToken(signerToken);
        Objects.requireNonNull(documentHashes, "documentHashes");

        ObjectNode body = MAPPER.createObjectNode();
        ObjectNode kmsData = body.putObject("kms_data");
        kmsData.put("url", pscServiceUrl);
        kmsData.put("token", signerToken);
        body.put("algoritmoHash", "SHA256");
        body.put("formatoAssinatura", "HASH");
        body.put("formatoDadosEntrada", "Base64");
        body.put("padrao", "CADES");
        body.put("perfil", "BASIC");
        ArrayNode hashes = body.putArray("hashes");
        for (byte[] documentHash : documentHashes) {
            hashes.add(EncodingUtils.toBase64(documentHash));
        }

        Map<String, String> headers = applicationHeaders();
        headers.put("kms_type", "PSC");
        String response = httpClient.postJson(BryEndpoints.cmsSignatureUrl(environment), headers, body.toString());
        return parseCmsSignatures(response, documentHashes.size());
    }

    private Map<String, String> applicationHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + applicationJwt());
        return headers;
    }

    private synchronized String applicationJwt() {
        if (cachedApplicationJwt != null && Instant.now().isBefore(applicationJwtExpiresAt)) {
            return cachedApplicationJwt;
        }
        String form = "grant_type=client_credentials"
                + "&client_id=" + urlEncode(clientId)
                + "&client_secret=" + urlEncode(clientSecret);
        try {
            String response = httpClient.postForm(BryEndpoints.cloudTokenUrl(environment), Map.of(), form);
            OAuth2TokenResponse token = MAPPER.readValue(response, OAuth2TokenResponse.class);
            if (token.accessToken() == null || token.accessToken().isBlank()) {
                throw new PscAuthenticationException("Bry Cloud token response did not include access_token");
            }
            cachedApplicationJwt = token.accessToken();
            long ttl = Math.max(1, token.expiresIn() - EXPIRY_SKEW_SECONDS);
            applicationJwtExpiresAt = Instant.now().plusSeconds(ttl);
            return cachedApplicationJwt;
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscAuthenticationException("Failed to parse Bry Cloud token response", e);
        }
    }

    private static BryAuthorizationLink parseLink(String response) {
        try {
            JsonNode node = MAPPER.readTree(response);
            String token = text(node, "token");
            String url = text(node, "url");
            if (token == null || token.isBlank() || url == null || url.isBlank()) {
                throw new PscAuthenticationException("Integra Bry link response did not include token and url");
            }
            return new BryAuthorizationLink(token, url);
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscAuthenticationException("Failed to parse Integra Bry authorization link", e);
        }
    }

    private static X509Certificate parseCertificate(String response) {
        try {
            JsonNode node = MAPPER.readTree(response);
            String content = text(node, "content");
            if (content == null || content.isBlank()) {
                throw new PscSigningException("Integra Bry certificate response did not include content");
            }
            byte[] encoded = EncodingUtils.fromBase64(content);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded));
        } catch (PscException e) {
            throw e;
        } catch (CertificateException e) {
            throw new PscSigningException("Invalid certificate returned by Integra Bry", e);
        } catch (Exception e) {
            throw new PscSigningException("Failed to parse Integra Bry certificate response", e);
        }
    }

    private static List<byte[]> parseCmsSignatures(String response, int expectedCount) {
        try {
            JsonNode node = MAPPER.readTree(response);
            JsonNode signatures = node.get("assinaturas");
            if (signatures == null || !signatures.isArray()) {
                throw new PscSigningException("Integra Bry CMS response did not include assinaturas");
            }
            if (signatures.size() != expectedCount) {
                throw new PscSigningException("Integra Bry returned "
                        + signatures.size() + " signatures, expected " + expectedCount);
            }
            List<byte[]> decoded = new ArrayList<>(expectedCount);
            for (JsonNode signature : signatures) {
                if (signature == null || signature.asText().isBlank()) {
                    throw new PscSigningException("Integra Bry returned an empty CMS signature");
                }
                decoded.add(EncodingUtils.fromBase64(signature.asText()));
            }
            return List.copyOf(decoded);
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscSigningException("Failed to parse Integra Bry CMS response", e);
        }
    }

    private static void validateSignerToken(String signerToken) {
        if (signerToken == null || signerToken.isBlank()) {
            throw new IllegalArgumentException("signerToken must not be blank");
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
