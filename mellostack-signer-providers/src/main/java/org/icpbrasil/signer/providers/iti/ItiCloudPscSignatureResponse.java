package org.icpbrasil.signer.providers.iti;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
final class ItiCloudPscSignatureResponse {

    @JsonProperty("certificate_alias")
    private String certificateAlias;

    @JsonProperty("signatures")
    private List<SignatureEntry> signatures;

    List<SignatureEntry> signatures() {
        return signatures != null ? signatures : List.of();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class SignatureEntry {

        @JsonProperty("raw_signature")
        private String rawSignature;

        String rawSignature() {
            return rawSignature;
        }
    }
}
