package org.icpbrasil.signer.providers.iti;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
final class ItiCloudPscCertificateDiscoveryResponse {

    @JsonProperty("status")
    private String status;

    @JsonProperty("certificates")
    private List<CertificateEntry> certificates;

    String status() {
        return status;
    }

    List<CertificateEntry> certificates() {
        return certificates != null ? certificates : List.of();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class CertificateEntry {

        @JsonProperty("alias")
        private String alias;

        @JsonProperty("certificate")
        private String certificate;

        String alias() {
            return alias;
        }

        String certificate() {
            return certificate;
        }
    }
}
