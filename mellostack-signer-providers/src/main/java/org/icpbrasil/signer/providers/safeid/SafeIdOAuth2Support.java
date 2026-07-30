package org.icpbrasil.signer.providers.safeid;

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
 * Utilitários OAuth2 SafeID (Safeweb) para a aplicação host (Authorization Code + PKCE).
 */
public final class SafeIdOAuth2Support {

    private final ItiCloudPscOAuth2Support delegate;

    SafeIdOAuth2Support(
            Environment environment,
            String clientId,
            String clientSecret,
            HttpClientFacade httpClient) {
        this.delegate = new ItiCloudPscOAuth2Support(
                new ItiCloudPscEndpoints(SafeIdEndpoints.baseUrl(environment)),
                clientId,
                clientSecret,
                httpClient
        );
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
        return delegate.tokenClient();
    }

    public String clientId() {
        return delegate.clientId();
    }

    public String clientSecret() {
        return delegate.clientSecret();
    }

    static SafeIdOAuth2Support create(
            Environment environment,
            String clientId,
            String clientSecret,
            HttpClientConfig httpClientConfig) {
        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        return new SafeIdOAuth2Support(environment, clientId, clientSecret, httpClient);
    }
}
