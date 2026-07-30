package org.icpbrasil.signer.providers.oauth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Resposta do endpoint OAuth2 {@code /oauth/token}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class OAuth2TokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("expires_in")
    private long expiresIn;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("refresh_token")
    private String refreshToken;

    public String accessToken() {
        return accessToken;
    }

    public long expiresIn() {
        return expiresIn;
    }

    public String tokenType() {
        return tokenType;
    }

    public String refreshToken() {
        return refreshToken;
    }
}
