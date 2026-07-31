package org.icpbrasil.signer.providers.oauth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2AuthorizationUrlBuilderTest {

    @Test
    void buildsAuthorizationUrlWithPkceAndScope() {
        String url = new OAuth2AuthorizationUrlBuilder("https://psc.test.local/v0/oauth/authorize")
                .clientId("client-id")
                .redirectUri("https://app/callback")
                .state("state-xyz")
                .codeChallenge("challenge-value")
                .scope(OAuth2Scope.SIGNATURE_SESSION)
                .loginHint("user@example.com")
                .lifetimeSeconds(900)
                .build();

        assertTrue(url.startsWith("https://psc.test.local/v0/oauth/authorize?"));
        assertTrue(url.contains("client_id=client-id"));
        assertTrue(url.contains("response_type=code"));
        assertTrue(url.contains("code_challenge=challenge-value"));
        assertTrue(url.contains("code_challenge_method=S256"));
        assertTrue(url.contains("scope=signature_session"));
        assertTrue(url.contains("login_hint=user%40example.com"));
        assertTrue(url.contains("lifetime=900"));
    }
}
