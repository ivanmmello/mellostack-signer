package org.icpbrasil.signer.providers.birdid;

import org.icpbrasil.signer.model.Environment;

/**
 * Endpoints Bird ID (Soluti) por ambiente.
 *
 * @see <a href="https://docs.vaultid.com.br/workspace/cloud/api/">Bird ID API</a>
 */
public final class BirdIdEndpoints {

    private static final String PRODUCTION_BASE = "https://api.birdid.com.br";
    private static final String HOMOLOGATION_BASE = "https://apihom.birdid.com.br";

    private BirdIdEndpoints() {
    }

    public static String baseUrl(Environment environment) {
        return switch (environment) {
            case PRODUCTION -> PRODUCTION_BASE;
            case HOMOLOGATION -> HOMOLOGATION_BASE;
        };
    }

    public static String authorizeUrl(Environment environment) {
        return baseUrl(environment) + "/v0/oauth/authorize";
    }

    public static String tokenUrl(Environment environment) {
        return baseUrl(environment) + "/v0/oauth/token";
    }

    public static String certificateDiscoveryUrl(Environment environment) {
        return baseUrl(environment) + "/v0/oauth/certificate-discovery";
    }

    public static String signatureUrl(Environment environment) {
        return baseUrl(environment) + "/v0/oauth/signature";
    }
}
