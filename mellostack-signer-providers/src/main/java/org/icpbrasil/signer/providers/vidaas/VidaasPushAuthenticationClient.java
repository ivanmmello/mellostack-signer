package org.icpbrasil.signer.providers.vidaas;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.exception.PscAuthenticationException;
import org.icpbrasil.signer.providers.exception.PscException;
import org.icpbrasil.signer.providers.http.HttpClientFacade;

import java.util.Objects;

/**
 * Polling da autenticação push VIDaaS ({@code /valid/api/v1/trusted-services/authentications}).
 * <p>
 * Após {@link VidaasOAuth2Support#buildPushAuthorizationUrl}, a aplicação host deve consultar
 * este endpoint (intervalo mínimo de 1 segundo) até receber o {@code authorizationToken}
 * para troca no {@link org.icpbrasil.signer.providers.oauth.OAuth2TokenClient}.
 */
public final class VidaasPushAuthenticationClient {

    static final long MIN_POLL_INTERVAL_MS = 1_000L;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Environment environment;
    private final HttpClientFacade httpClient;

    public VidaasPushAuthenticationClient(Environment environment, HttpClientFacade httpClient) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    /**
     * Consulta o status da autenticação push. Retorna vazio enquanto pendente.
     */
    public java.util.Optional<String> pollAuthorizationToken(String pushCode) {
        validatePushCode(pushCode);
        String response = httpClient.get(
                VidaasEndpoints.pushAuthenticationsUrl(environment) + "?code=" + pushCode,
                java.util.Map.of()
        );
        return parseAuthorizationToken(response);
    }

    static void validatePushCode(String pushCode) {
        if (pushCode == null || pushCode.isBlank()) {
            throw new IllegalArgumentException("pushCode must not be blank");
        }
        if (pushCode.length() > 512) {
            throw new IllegalArgumentException("pushCode exceeds maximum allowed length");
        }
    }

    private java.util.Optional<String> parseAuthorizationToken(String responseJson) {
        try {
            VidaasPushAuthenticationResponse parsed =
                    MAPPER.readValue(responseJson, VidaasPushAuthenticationResponse.class);
            if (parsed.authorizationToken() == null || parsed.authorizationToken().isBlank()) {
                return java.util.Optional.empty();
            }
            return java.util.Optional.of(parsed.authorizationToken());
        } catch (PscException e) {
            throw e;
        } catch (Exception e) {
            throw new PscAuthenticationException("Failed to parse VIDaaS push authentication response", e);
        }
    }
}
