package com.mellostack.signer.demo.service;

import com.mellostack.signer.demo.config.DemoProperties;
import com.mellostack.signer.demo.psc.DemoPscRegistry;
import com.mellostack.signer.demo.session.SigningSession;
import com.mellostack.signer.demo.session.SigningSessionStatus;
import org.icpbrasil.signer.providers.bry.BryAuthorizationRequest;
import org.icpbrasil.signer.providers.bry.BryProvider;
import org.icpbrasil.signer.providers.bry.BryPsc;
import org.icpbrasil.signer.providers.bry.BrySignatureScope;
import org.icpbrasil.signer.providers.oauth.OAuth2TokenClient;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Service
public class OAuthFlowService {

    private final DemoProperties properties;
    private final DemoPscRegistry pscRegistry;
    private final SigningSessionService sessionService;

    public OAuthFlowService(
            DemoProperties properties,
            DemoPscRegistry pscRegistry,
            SigningSessionService sessionService) {
        this.properties = properties;
        this.pscRegistry = pscRegistry;
        this.sessionService = sessionService;
    }

    public URI startAuthorization(String sessionId) {
        SigningSession session = sessionService.require(sessionId);
        DemoPscRegistry.DemoPscBundle bundle = pscRegistry.bundleForSession(session.providerId(), session.environment());
        if (bundle.oauth().completesWithoutAuthorizationCode()) {
            BryProvider bry = (BryProvider) bundle.provider();
            var link = bry.authorization().createLink(BryAuthorizationRequest.builder()
                    .psc(BryPsc.fromApiName(properties.psc().bryPsc()))
                    .redirectUri(properties.oauthRedirectUri())
                    .state(session.id())
                    .scope(BrySignatureScope.SINGLE_SIGNATURE)
                    .numberOfDocuments(1)
                    .build());
            session.setAccessToken(link.signerToken());
            session.setCodeVerifier("bry-link");
            return URI.create(link.authorizationUrl());
        }

        var pkce = bundle.oauth().generatePkceChallenge();
        session.setCodeVerifier(pkce.codeVerifier());

        String authorizationUrl = bundle.oauth().buildAuthorizationUrl(
                pkce,
                properties.oauthRedirectUri(),
                session.id());

        return URI.create(authorizationUrl);
    }

    public boolean completesWithoutAuthorizationCode(String sessionId) {
        SigningSession session = sessionService.require(sessionId);
        return pscRegistry.bundleForSession(session.providerId(), session.environment())
                .oauth()
                .completesWithoutAuthorizationCode();
    }

    public URI completeAuthorization(String sessionId, String authorizationCode) {
        SigningSession session = sessionService.require(sessionId);
        DemoPscRegistry.DemoPscBundle bundle = pscRegistry.bundleForSession(session.providerId(), session.environment());
        if (bundle.oauth().completesWithoutAuthorizationCode()) {
            if (session.accessToken() == null || session.accessToken().isBlank()) {
                throw new IllegalStateException("Missing Integra Bry signer credential for session " + sessionId);
            }
            session.setStatus(SigningSessionStatus.AUTHORIZED);
            return successRedirect(session);
        }

        if (session.codeVerifier() == null || session.codeVerifier().isBlank()) {
            throw new IllegalStateException("Missing PKCE verifier for session " + sessionId);
        }

        OAuth2TokenClient tokenClient = bundle.oauth().tokenClient();
        var token = tokenClient.exchangeAuthorizationCode(new OAuth2TokenClient.AuthorizationCodeRequest(
                bundle.oauth().clientId(),
                bundle.oauth().clientSecret(),
                authorizationCode,
                properties.oauthRedirectUri(),
                session.codeVerifier(),
                null));

        session.setAccessToken(token.accessToken());
        session.setStatus(SigningSessionStatus.AUTHORIZED);
        return successRedirect(session);
    }

    private URI successRedirect(SigningSession session) {
        return UriComponentsBuilder.fromUriString(properties.frontendUrl())
                .path("/")
                .queryParam("sessionId", session.id())
                .queryParam("oauth", "success")
                .build()
                .toUri();
    }

    public URI failureRedirect(String sessionId, String message) {
        SigningSession session = sessionService.require(sessionId);
        sessionService.markFailed(session, message);
        return UriComponentsBuilder.fromUriString(properties.frontendUrl())
                .path("/")
                .queryParam("sessionId", session.id())
                .queryParam("oauth", "error")
                .queryParam("message", message)
                .build()
                .toUri();
    }
}
