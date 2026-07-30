package org.icpbrasil.signer.providers.http;

import org.icpbrasil.signer.providers.exception.PscHttpException;
import org.icpbrasil.signer.providers.security.SensitiveRedactor;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Cliente HTTP com TLS obrigatório, timeouts e redação de dados sensíveis em erros.
 */
public final class SecureHttpClient implements HttpClientFacade {

    private final HttpClient httpClient;
    private final HttpClientConfig config;

    public SecureHttpClient(HttpClientConfig config) {
        this(config, createHttpClient(config));
    }

    SecureHttpClient(HttpClientConfig config, HttpClient httpClient) {
        this.config = Objects.requireNonNull(config, "config");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    public HttpClientConfig config() {
        return config;
    }

    public String get(String url, Map<String, String> headers) {
        return exchange(buildRequest("GET", url, headers, null));
    }

    public String postJson(String url, Map<String, String> headers, String jsonBody) {
        Objects.requireNonNull(jsonBody, "jsonBody");
        return exchange(buildRequest("POST", url, headers, jsonBody));
    }

    private HttpRequest buildRequest(String method, String url, Map<String, String> headers, String body) {
        URI uri = URI.create(url);
        config.validateUrl(uri);

        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(config.requestTimeout())
                .header("Accept", "application/json");

        Map<String, String> safeHeaders = headers != null ? headers : Map.of();
        for (Map.Entry<String, String> entry : safeHeaders.entrySet()) {
            builder.header(entry.getKey(), entry.getValue());
        }

        if (body != null) {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            builder.GET();
        }
        return builder.build();
    }

    private String exchange(HttpRequest request) {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            String responseBody = response.body() != null ? response.body() : "";

            if (status >= 200 && status < 300) {
                return responseBody;
            }

            String message = "PSC HTTP " + status + ": " + SensitiveRedactor.redact(truncate(responseBody));
            if (status == 401 || status == 403) {
                throw new org.icpbrasil.signer.providers.exception.PscAuthenticationException(message);
            }
            if (status >= 400 && status < 500) {
                throw new org.icpbrasil.signer.providers.exception.PscSigningException(message);
            }
            throw new PscHttpException(message, status);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PscHttpException("PSC HTTP request interrupted", 0, e);
        } catch (IOException e) {
            throw new PscHttpException("PSC HTTP request failed: " + e.getMessage(), 0, e);
        }
    }

    private static String truncate(String value) {
        if (value.length() <= 512) {
            return value;
        }
        return value.substring(0, 512) + "...";
    }

    private static HttpClient createHttpClient(HttpClientConfig config) {
        return HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public static Map<String, String> bearerHeaders(String accessToken) {
        Objects.requireNonNull(accessToken, "accessToken");
        if (accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + accessToken);
        return Map.copyOf(headers);
    }
}
