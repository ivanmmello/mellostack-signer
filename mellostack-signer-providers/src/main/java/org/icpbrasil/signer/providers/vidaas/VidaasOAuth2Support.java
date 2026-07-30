package org.icpbrasil.signer.providers.vidaas;

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
 * Utilitários OAuth2 VIDaaS (Valid) para a aplicação host (Authorization Code + PKCE).
 * <p>
 * Suporta fluxo QR Code (redirect HTTP) e push ({@code redirect_uri=push://}).
 */
public final class VidaasOAuth2Support {

    private static final String PUSH_REDIRECT_URI = "push://";

    private final Environment environment;
    private final ItiCloudPscOAuth2Support delegate;
    private final VidaasPushAuthenticationClient pushAuthenticationClient;

    VidaasOAuth2Support(
            Environment environment,
            String clientId,
            String clientSecret,
            HttpClientFacade httpClient) {
        this.environment = environment;
        this.delegate = new ItiCloudPscOAuth2Support(
                new ItiCloudPscEndpoints(VidaasEndpoints.baseUrl(environment)),
                clientId,
                clientSecret,
                httpClient
        );
        this.pushAuthenticationClient = new VidaasPushAuthenticationClient(environment, httpClient);
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

    /**
     * URL de autorização push — {@code login_hint} (CPF/CNPJ) é obrigatório.
     */
    public String buildPushAuthorizationUrl(
            OAuth2PkceGenerator.PkceChallenge pkce,
            String cpfOrCnpj,
            OAuth2Scope scope,
            Integer lifetimeSeconds) {
        if (cpfOrCnpj == null || cpfOrCnpj.isBlank()) {
            throw new IllegalArgumentException("cpfOrCnpj must not be blank for push authorization");
        }
        return delegate.buildAuthorizationUrl(
                pkce,
                PUSH_REDIRECT_URI,
                "NONE",
                scope != null ? scope : OAuth2Scope.SIGNATURE_SESSION,
                cpfOrCnpj,
                lifetimeSeconds
        );
    }

    public VidaasPushAuthenticationClient pushAuthentication() {
        return pushAuthenticationClient;
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

    public Environment environment() {
        return environment;
    }

    static VidaasOAuth2Support create(
            Environment environment,
            String clientId,
            String clientSecret,
            HttpClientConfig httpClientConfig) {
        SecureHttpClient httpClient = new SecureHttpClient(httpClientConfig);
        return new VidaasOAuth2Support(environment, clientId, clientSecret, httpClient);
    }
}
