package org.icpbrasil.signer.providers.vidaas;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Resposta do polling de autenticação push VIDaaS.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
record VidaasPushAuthenticationResponse(
        @JsonProperty("authorizationToken") String authorizationToken,
        @JsonProperty("redirectUrl") String redirectUrl) {
}
