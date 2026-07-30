package org.icpbrasil.signer.providers.oauth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2PkceGeneratorTest {

    @Test
    void generatesUniqueVerifierAndValidChallenge() {
        OAuth2PkceGenerator.PkceChallenge first = OAuth2PkceGenerator.generate();
        OAuth2PkceGenerator.PkceChallenge second = OAuth2PkceGenerator.generate();

        assertNotEquals(first.codeVerifier(), second.codeVerifier());
        assertEquals(OAuth2PkceGenerator.s256(first.codeVerifier()), first.codeChallenge());
        assertTrue(first.codeVerifier().length() >= 43);
    }

    @Test
    void authorizationUrlIncludesPkceAndSignatureScope() {
        OAuth2PkceGenerator.PkceChallenge pkce = OAuth2PkceGenerator.generate();
        String url = new OAuth2AuthorizationUrlBuilder("https://api.birdid.com.br/v0/oauth/authorize")
                .clientId("client")
                .redirectUri("https://app.example/callback")
                .state("state-123")
                .codeChallenge(pkce.codeChallenge())
                .scope(OAuth2Scope.SIGNATURE_SESSION)
                .build();

        assertTrue(url.contains("code_challenge="));
        assertTrue(url.contains("code_challenge_method=S256"));
        assertTrue(url.contains("scope=signature_session"));
        assertTrue(url.contains("response_type=code"));
    }
}
