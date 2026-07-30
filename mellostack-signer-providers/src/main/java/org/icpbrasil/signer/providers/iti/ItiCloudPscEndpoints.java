package org.icpbrasil.signer.providers.iti;

import java.util.Objects;

/**
 * Endpoints REST padrão ITI para PSCs em nuvem ({@code /v0/oauth/*}).
 */
public record ItiCloudPscEndpoints(String baseUrl) {

    private static final String OAUTH_PREFIX = "/v0/oauth";

    public ItiCloudPscEndpoints {
        Objects.requireNonNull(baseUrl, "baseUrl");
        if (baseUrl.isBlank()) {
            throw new IllegalArgumentException("baseUrl must not be blank");
        }
    }

    public String authorizeUrl() {
        return normalizedBase() + OAUTH_PREFIX + "/authorize";
    }

    public String tokenUrl() {
        return normalizedBase() + OAUTH_PREFIX + "/token";
    }

    public String certificateDiscoveryUrl() {
        return normalizedBase() + OAUTH_PREFIX + "/certificate-discovery";
    }

    public String signatureUrl() {
        return normalizedBase() + OAUTH_PREFIX + "/signature";
    }

    private String normalizedBase() {
        String trimmed = baseUrl.trim();
        if (trimmed.endsWith("/")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}
