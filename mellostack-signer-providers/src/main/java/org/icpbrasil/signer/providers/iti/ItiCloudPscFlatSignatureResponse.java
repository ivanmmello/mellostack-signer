package org.icpbrasil.signer.providers.iti;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Resposta de assinatura em formato plano (ex.: Safeweb PSC RO).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
final class ItiCloudPscFlatSignatureResponse {

    @JsonProperty("status")
    private String status;

    @JsonProperty("raw_signature")
    private String rawSignature;

    String status() {
        return status;
    }

    String rawSignature() {
        return rawSignature;
    }
}
