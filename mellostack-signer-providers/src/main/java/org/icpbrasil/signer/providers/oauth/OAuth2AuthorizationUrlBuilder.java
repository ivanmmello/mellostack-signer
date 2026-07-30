package org.icpbrasil.signer.providers.oauth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Constrói URL de autorização OAuth2 Authorization Code + PKCE.
 */
public final class OAuth2AuthorizationUrlBuilder {

    private final String authorizeEndpoint;
    private String clientId;
    private String redirectUri;
    private String state;
    private String codeChallenge;
    private OAuth2Scope scope = OAuth2Scope.SIGNATURE_SESSION;
    private String loginHint;
    private Integer lifetimeSeconds;

    public OAuth2AuthorizationUrlBuilder(String authorizeEndpoint) {
        this.authorizeEndpoint = Objects.requireNonNull(authorizeEndpoint, "authorizeEndpoint");
        if (authorizeEndpoint.isBlank()) {
            throw new IllegalArgumentException("authorizeEndpoint must not be blank");
        }
    }

    public OAuth2AuthorizationUrlBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public OAuth2AuthorizationUrlBuilder redirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    public OAuth2AuthorizationUrlBuilder state(String state) {
        this.state = state;
        return this;
    }

    public OAuth2AuthorizationUrlBuilder codeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
        return this;
    }

    public OAuth2AuthorizationUrlBuilder scope(OAuth2Scope scope) {
        this.scope = Objects.requireNonNull(scope, "scope");
        return this;
    }

    public OAuth2AuthorizationUrlBuilder loginHint(String loginHint) {
        this.loginHint = loginHint;
        return this;
    }

    public OAuth2AuthorizationUrlBuilder lifetimeSeconds(int lifetimeSeconds) {
        if (lifetimeSeconds <= 0) {
            throw new IllegalArgumentException("lifetimeSeconds must be positive");
        }
        this.lifetimeSeconds = lifetimeSeconds;
        return this;
    }

    public String build() {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(redirectUri, "redirectUri");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(codeChallenge, "codeChallenge");
        Objects.requireNonNull(scope, "scope");

        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        params.put("state", state);
        params.put("code_challenge", codeChallenge);
        params.put("code_challenge_method", "S256");
        params.put("scope", scope.value());
        if (loginHint != null && !loginHint.isBlank()) {
            params.put("login_hint", loginHint);
        }
        if (lifetimeSeconds != null) {
            params.put("lifetime", String.valueOf(lifetimeSeconds));
        }

        String query = params.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(Collectors.joining("&"));

        return authorizeEndpoint + "?" + query;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
