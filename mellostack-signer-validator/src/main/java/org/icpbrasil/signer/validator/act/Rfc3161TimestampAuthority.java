package org.icpbrasil.signer.validator.act;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * Cliente RFC 3161 (HTTP {@code application/timestamp-query}) para ACT credenciada.
 */
public final class Rfc3161TimestampAuthority implements TimestampAuthority {

    private static final String TIMESTAMP_QUERY = "application/timestamp-query";

    private final ActClientConfig config;
    private final HttpClient httpClient;

    public Rfc3161TimestampAuthority(ActClientConfig config) {
        this(config, HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    Rfc3161TimestampAuthority(ActClientConfig config, HttpClient httpClient) {
        this.config = Objects.requireNonNull(config, "config");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    public ActClientConfig config() {
        return config;
    }

    @Override
    public byte[] requestTimestampToken(byte[] messageImprint, DigestAlgorithm digestAlgorithm) {
        validateImprint(messageImprint, digestAlgorithm);
        try {
            TimeStampRequest request = buildRequest(messageImprint, digestAlgorithm);
            byte[] responseBody = postTimestampQuery(request.getEncoded());
            return parseToken(request, responseBody);
        } catch (ActException e) {
            throw e;
        } catch (Exception e) {
            throw new ActException("Failed to request timestamp from ACT", e);
        }
    }

    private TimeStampRequest buildRequest(byte[] messageImprint, DigestAlgorithm digestAlgorithm) throws IOException {
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        if (config.policyOid() != null && !config.policyOid().isBlank()) {
            generator.setReqPolicy(new ASN1ObjectIdentifier(config.policyOid()));
        }
        return generator.generate(digestOid(digestAlgorithm), messageImprint);
    }

    private byte[] postTimestampQuery(byte[] requestBody) throws IOException, InterruptedException {
        URI tsaUrl = config.tsaUrl();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(tsaUrl)
                .timeout(config.readTimeout())
                .header("Content-Type", TIMESTAMP_QUERY)
                .header("Accept", TIMESTAMP_QUERY)
                .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody))
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new ActException("ACT returned HTTP " + response.statusCode());
        }
        byte[] body = response.body();
        if (body == null || body.length == 0) {
            throw new ActException("ACT returned an empty timestamp response");
        }
        return body;
    }

    private static byte[] parseToken(TimeStampRequest request, byte[] responseBody) throws Exception {
        TimeStampResponse response = new TimeStampResponse(responseBody);
        response.validate(request);
        TimeStampToken token = response.getTimeStampToken();
        if (token == null) {
            throw new ActException("ACT timestamp response did not include a token");
        }
        return token.getEncoded();
    }

    private static ASN1ObjectIdentifier digestOid(DigestAlgorithm digestAlgorithm) {
        return switch (digestAlgorithm) {
            case SHA256 -> NISTObjectIdentifiers.id_sha256;
            case SHA384 -> NISTObjectIdentifiers.id_sha384;
        };
    }

    private static void validateImprint(byte[] messageImprint, DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(messageImprint, "messageImprint");
        Objects.requireNonNull(digestAlgorithm, "digestAlgorithm");
        int expected = switch (digestAlgorithm) {
            case SHA256 -> 32;
            case SHA384 -> 48;
        };
        if (messageImprint.length != expected) {
            throw new IllegalArgumentException(
                    "messageImprint length must be " + expected + " bytes for " + digestAlgorithm);
        }
    }
}
