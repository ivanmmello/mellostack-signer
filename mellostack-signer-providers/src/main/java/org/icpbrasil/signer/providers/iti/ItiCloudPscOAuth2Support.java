package org.icpbrasil.signer.providers.iti;

import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.oauth.OAuth2AuthorizationUrlBuilder;
import org.icpbrasil.signer.providers.oauth.OAuth2PkceGenerator;
import org.icpbrasil.signer.providers.oauth.OAuth2Scope;
import org.icpbrasil.signer.providers.oauth.OAuth2TokenClient;

import java.util.Objects;

/**
 * OAuth2 Authorization Code + PKCE para PSCs no padrão ITI ({@code /v0/oauth/*}).
 */
public final class ItiCloudPscOAuth2Support {

    private final ItiCloudPscEndpoints endpoints;
    private final String clientId;
    private final String clientSecret;
    private final HttpClientFacade httpClient;

    public ItiCloudPscOAuth2Support(
            ItiCloudPscEndpoints endpoints,
            String clientId,
            String clientSecret,
            HttpClientFacade httpClient) {
        this.endpoints = Objects.requireNonNull(endpoints, "endpoints");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.clientSecret = Objects.requireNonNull(clientSecret, "clientSecret");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    public OAuth2PkceGenerator.PkceChallenge generatePkceChallenge() {
        return OAuth2PkceGenerator.generate();
    }

    public String buildAuthorizationUrl(
            OAuth2PkceGenerator.PkceChallenge pkce,
            String redirectUri,
            String state) {
        return buildAuthorizationUrl(pkce, redirectUri, state, OAuth2Scope.SIGNATURE_SESSION, null, null);
    }

    public String buildAuthorizationUrl(
            OAuth2PkceGenerator.PkceChallenge pkce,
            String redirectUri,
            String state,
            OAuth2Scope scope,
            String loginHint,
            Integer lifetimeSeconds) {
        Objects.requireNonNull(pkce, "pkce");
        Objects.requireNonNull(scope, "scope");
        if (scope == OAuth2Scope.AUTHENTICATION_SESSION) {
            throw new IllegalArgumentException(
                    "Use SIGNATURE_SESSION (or single/multi_signature) for document signing");
        }

        OAuth2AuthorizationUrlBuilder builder = new OAuth2AuthorizationUrlBuilder(endpoints.authorizeUrl())
                .clientId(clientId)
                .redirectUri(redirectUri)
                .state(state)
                .codeChallenge(pkce.codeChallenge())
                .scope(scope);

        if (loginHint != null && !loginHint.isBlank()) {
            builder.loginHint(loginHint);
        }
        if (lifetimeSeconds != null) {
            builder.lifetimeSeconds(lifetimeSeconds);
        }
        return builder.build();
    }

    public OAuth2TokenClient tokenClient() {
        return new OAuth2TokenClient(endpoints.tokenUrl(), httpClient);
    }

    public String clientId() {
        return clientId;
    }

    public String clientSecret() {
        return clientSecret;
    }
}
