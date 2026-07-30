package org.icpbrasil.signer.providers.vidaas;

import org.icpbrasil.signer.model.Environment;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VidaasPushAuthenticationClientTest {

    @Test
    void parsesAuthorizationTokenWhenReady() {
        FakeHttpClient http = new FakeHttpClient("""
                {
                  "authorizationToken": "jwt-token-here",
                  "redirectUrl": "push://?code=abc"
                }
                """);

        VidaasPushAuthenticationClient client =
                new VidaasPushAuthenticationClient(Environment.HOMOLOGATION, http);

        Optional<String> token = client.pollAuthorizationToken("push-code-123");

        assertTrue(token.isPresent());
        assertEquals("jwt-token-here", token.get());
        assertTrue(http.lastUrl.contains("code=push-code-123"));
    }

    @Test
    void returnsEmptyWhilePending() {
        FakeHttpClient http = new FakeHttpClient("{}");

        VidaasPushAuthenticationClient client =
                new VidaasPushAuthenticationClient(Environment.HOMOLOGATION, http);

        assertTrue(client.pollAuthorizationToken("push-code-123").isEmpty());
    }

    private static final class FakeHttpClient implements org.icpbrasil.signer.providers.http.HttpClientFacade {

        private final String responseBody;
        private String lastUrl;

        FakeHttpClient(String responseBody) {
            this.responseBody = responseBody;
        }

        @Override
        public String get(String url, java.util.Map<String, String> headers) {
            lastUrl = url;
            return responseBody;
        }

        @Override
        public String postJson(String url, java.util.Map<String, String> headers, String jsonBody) {
            lastUrl = url;
            return responseBody;
        }
    }
}
