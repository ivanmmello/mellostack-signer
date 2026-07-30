package org.icpbrasil.signer.providers.birdid;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
final class BirdIdSignatureResponse {

    @JsonProperty("certificate_alias")
    private String certificateAlias;

    @JsonProperty("signatures")
    private List<SignatureEntry> signatures;

    String certificateAlias() {
        return certificateAlias;
    }

    List<SignatureEntry> signatures() {
        return signatures != null ? signatures : List.of();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class SignatureEntry {

        @JsonProperty("id")
        private String id;

        @JsonProperty("raw_signature")
        private String rawSignature;

        String id() {
            return id;
        }

        String rawSignature() {
            return rawSignature;
        }
    }
}
