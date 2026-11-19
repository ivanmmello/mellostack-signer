package org.icpbrasil.signer.providers.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.icpbrasil.signer.providers.exception.PscAuthenticationException;
import org.icpbrasil.signer.providers.exception.PscException;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.http.SecureHttpClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Troca authorization code por access token (OAuth2 + PKCE).
 */
public final class OAuth2TokenClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClientFacade httpClient;
    private final String tokenEndpoint;
    private final BodyEncoding bodyEncoding;

    public OAuth2TokenClient(String tokenEndpoint, HttpClientFacade httpClient) {
        this(tokenEndpoint, httpClient, BodyEncoding.JSON);
    }

    /**
     * @param bodyEncoding {@link BodyEncoding#FORM} para PSCs que exigem
     *                     {@code application/x-www-form-urlencoded} (SerproID)
     */
    public OAuth2TokenClient(String tokenEndpoint, HttpClientFacade httpClient, BodyEncoding bodyEncoding) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.bodyEncoding = Objects.requireNonNull(bodyEncoding, "bodyEncoding");
        if (tokenEndpoint.isBlank()) {
            throw new IllegalArgumentException("tokenEndpoint must not be blank");
        }
    }

    public static OAuth2TokenClient formUrlEncoded(String tokenEndpoint, HttpClientFacade httpClient) {
        return new OAuth2TokenClient(tokenEndpoint, httpClient, BodyEncoding.FORM);
    }

    public OAuth2TokenResponse exchangeAuthorizationCode(AuthorizationCodeRequest request) {
        Objects.requireNonNull(request, "request");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "authorization_code");
        body.put("code", request.authorizationCode());
        body.put("redirect_uri", request.redirectUri());
        body.put("client_id", request.clientId());
        body.put("client_secret", request.clientSecret());
        body.put("code_verifier", request.codeVerifier());
        if (request.lifetimeSeconds() != null) {
            body.put("lifetime", request.lifetimeSeconds());
        }

        return postToken(body);
    }

    public OAuth2TokenResponse refreshToken(RefreshTokenRequest request) {
        Objects.requireNonNull(request, "request");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "refresh_token");
        body.put("refresh_token", request.refreshToken());
        body.put("client_id", request.clientId());
        body.put("client_secret", request.clientSecret());

        return postToken(body);
    }

    private OAuth2TokenResponse postToken(Map<String, Object> body) {
        try {
            String response = switch (bodyEncoding) {
                case JSON -> httpClient.postJson(tokenEndpoint, Map.of(), MAPPER.writeValueAsString(body));
                case FORM -> httpClient.postForm(tokenEndpoint, Map.of(), toForm(body));
            };
            OAuth2TokenResponse token = MAPPER.readValue(response, OAuth2TokenResponse.class);
            if (token.accessToken() == null || token.accessToken().isBlank()) {
                throw new PscAuthenticationException("OAuth2 token response did not include access_token");
            }
            return token;
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscAuthenticationException("Failed to parse OAuth2 token response", e);
        }
    }

    public record AuthorizationCodeRequest(
            String clientId,
            String clientSecret,
            String authorizationCode,
            String redirectUri,
            String codeVerifier,
            Integer lifetimeSeconds) {
    }

    public record RefreshTokenRequest(
            String clientId,
            String clientSecret,
            String refreshToken) {
    }

    public enum BodyEncoding {
        JSON,
        FORM
    }

    private static String toForm(Map<String, Object> body) {
        return body.entrySet().stream()
                .filter(entry -> entry.getValue() != null)
                .map(entry -> urlEncode(entry.getKey()) + "=" + urlEncode(String.valueOf(entry.getValue())))
                .collect(Collectors.joining("&"));
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
