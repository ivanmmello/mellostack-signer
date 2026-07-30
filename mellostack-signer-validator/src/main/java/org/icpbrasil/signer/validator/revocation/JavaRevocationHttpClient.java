package org.icpbrasil.signer.validator.revocation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * Cliente HTTP seguro (HTTPS) para CRL/OCSP.
 */
public final class JavaRevocationHttpClient implements RevocationHttpClient {

    private static final Duration DEFAULT_CONNECT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_READ = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final Duration readTimeout;

    public JavaRevocationHttpClient() {
        this(HttpClient.newBuilder()
                .connectTimeout(DEFAULT_CONNECT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build(), DEFAULT_READ);
    }

    JavaRevocationHttpClient(HttpClient httpClient, Duration readTimeout) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.readTimeout = Objects.requireNonNull(readTimeout, "readTimeout");
    }

    @Override
    public byte[] get(String url) throws IOException {
        validateHttpsUrl(url);
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(readTimeout)
                    .GET()
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return validateResponse(response);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("CRL/OCSP request interrupted", e);
        }
    }

    @Override
    public byte[] post(String url, String contentType, byte[] body) throws IOException {
        validateHttpsUrl(url);
        Objects.requireNonNull(contentType, "contentType");
        Objects.requireNonNull(body, "body");
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(readTimeout)
                    .header("Content-Type", contentType)
                    .header("Accept", contentType)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return validateResponse(response);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("CRL/OCSP request interrupted", e);
        }
    }

    private static byte[] validateResponse(HttpResponse<byte[]> response) throws IOException {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("CRL/OCSP HTTP " + response.statusCode());
        }
        byte[] body = response.body();
        if (body == null || body.length == 0) {
            throw new IOException("CRL/OCSP empty response body");
        }
        return body;
    }

    private static void validateHttpsUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("url must not be blank");
        }
        URI uri = URI.create(url);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("CRL/OCSP URL must use HTTPS: " + url);
        }
    }
}
