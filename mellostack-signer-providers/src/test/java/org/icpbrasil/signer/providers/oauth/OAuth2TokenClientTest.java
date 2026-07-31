package org.icpbrasil.signer.providers.oauth;

import org.icpbrasil.signer.providers.exception.PscAuthenticationException;
import org.icpbrasil.signer.providers.http.HttpClientFacade;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2TokenClientTest {

    private static final String TOKEN_URL = "https://psc.test.local/v0/oauth/token";

    @Mock
    private HttpClientFacade httpClient;

    @Test
    void exchangesAuthorizationCode() {
        when(httpClient.postJson(eq(TOKEN_URL), anyMap(), org.mockito.ArgumentMatchers.anyString()))
                .thenReturn("""
                        {
                          "access_token": "access-123",
                          "token_type": "Bearer",
                          "expires_in": 3600,
                          "refresh_token": "refresh-456"
                        }
                        """);

        OAuth2TokenClient client = new OAuth2TokenClient(TOKEN_URL, httpClient);
        OAuth2TokenResponse response = client.exchangeAuthorizationCode(
                new OAuth2TokenClient.AuthorizationCodeRequest(
                        "client-id",
                        "client-secret",
                        "auth-code",
                        "https://app/callback",
                        "verifier",
                        900
                )
        );

        assertEquals("access-123", response.accessToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(3600, response.expiresIn());
        assertEquals("refresh-456", response.refreshToken());

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(httpClient).postJson(eq(TOKEN_URL), anyMap(), bodyCaptor.capture());
        String body = bodyCaptor.getValue();
        assertTrue(body.contains("\"grant_type\":\"authorization_code\""));
        assertTrue(body.contains("\"code_verifier\":\"verifier\""));
        assertTrue(body.contains("\"lifetime\":900"));
    }

    @Test
    void refreshesAccessToken() {
        when(httpClient.postJson(eq(TOKEN_URL), anyMap(), org.mockito.ArgumentMatchers.anyString()))
                .thenReturn("""
                        {
                          "access_token": "new-access",
                          "token_type": "Bearer",
                          "expires_in": 1800
                        }
                        """);

        OAuth2TokenClient client = new OAuth2TokenClient(TOKEN_URL, httpClient);
        OAuth2TokenResponse response = client.refreshToken(
                new OAuth2TokenClient.RefreshTokenRequest("client-id", "client-secret", "refresh-456")
        );

        assertEquals("new-access", response.accessToken());
    }

    @Test
    void rejectsTokenResponseWithoutAccessToken() {
        when(httpClient.postJson(eq(TOKEN_URL), anyMap(), org.mockito.ArgumentMatchers.anyString()))
                .thenReturn("{\"token_type\":\"Bearer\",\"expires_in\":3600}");

        OAuth2TokenClient client = new OAuth2TokenClient(TOKEN_URL, httpClient);

        assertThrows(PscAuthenticationException.class, () -> client.refreshToken(
                new OAuth2TokenClient.RefreshTokenRequest("client-id", "client-secret", "refresh-456")
        ));
    }
}
