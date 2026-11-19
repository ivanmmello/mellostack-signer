package org.icpbrasil.signer.providers.serproid;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.iti.ItiCloudPscEndpoints;
import org.icpbrasil.signer.providers.iti.ItiCloudPscOAuth2Support;
import org.icpbrasil.signer.providers.oauth.OAuth2PkceGenerator;
import org.icpbrasil.signer.providers.oauth.OAuth2Scope;
import org.icpbrasil.signer.providers.oauth.OAuth2TokenClient;

/**
 * OAuth2 Authorization Code + PKCE do SerproID.
 * <p>
 * A troca do {@code code} usa {@code application/x-www-form-urlencoded}.
 */
public final class SerproIdOAuth2Support {

    private final ItiCloudPscOAuth2Support delegate;
    private final HttpClientFacade httpClient;
    private final ItiCloudPscEndpoints endpoints;

    SerproIdOAuth2Support(
            Environment environment,
            String clientId,
            String clientSecret,
            HttpClientFacade httpClient) {
        this.endpoints = new ItiCloudPscEndpoints(SerproIdEndpoints.baseUrl(environment));
        this.httpClient = httpClient;
        this.delegate = new ItiCloudPscOAuth2Support(endpoints, clientId, clientSecret, httpClient);
    }

    public OAuth2PkceGenerator.PkceChallenge generatePkceChallenge() {
        return delegate.generatePkceChallenge();
    }

    public String buildAuthorizationUrl(
            OAuth2PkceGenerator.PkceChallenge pkce,
            String redirectUri,
            String state) {
        return delegate.buildAuthorizationUrl(pkce, redirectUri, state);
    }

    public String buildAuthorizationUrl(
            OAuth2PkceGenerator.PkceChallenge pkce,
            String redirectUri,
            String state,
            OAuth2Scope scope,
            String loginHint,
            Integer lifetimeSeconds) {
        return delegate.buildAuthorizationUrl(pkce, redirectUri, state, scope, loginHint, lifetimeSeconds);
    }

    public OAuth2TokenClient tokenClient() {
        return OAuth2TokenClient.formUrlEncoded(endpoints.tokenUrl(), httpClient);
    }

    public String clientId() {
        return delegate.clientId();
    }

    public String clientSecret() {
        return delegate.clientSecret();
    }

    static SerproIdOAuth2Support create(
            Environment environment,
            String clientId,
            String clientSecret,
            HttpClientConfig httpClientConfig) {
        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        return new SerproIdOAuth2Support(environment, clientId, clientSecret, httpClient);
    }
}
