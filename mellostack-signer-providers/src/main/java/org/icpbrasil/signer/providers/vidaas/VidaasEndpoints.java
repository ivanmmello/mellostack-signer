package org.icpbrasil.signer.providers.vidaas;

import org.icpbrasil.signer.model.Environment;

/**
 * Endpoints VIDaaS (Valid) por ambiente.
 *
 * @see <a href="https://valid-sa.atlassian.net/wiki/spaces/PDD/pages/958365697">Manual VIDaaS</a>
 */
public final class VidaasEndpoints {

    private static final String PRODUCTION_BASE = "https://certificado.vidaas.com.br";
    private static final String HOMOLOGATION_BASE = "https://hml-certificado.vidaas.com.br";

    private VidaasEndpoints() {
    }

    public static String baseUrl(Environment environment) {
        return switch (environment) {
            case PRODUCTION -> PRODUCTION_BASE;
            case HOMOLOGATION -> HOMOLOGATION_BASE;
        };
    }

    public static String pushAuthenticationsUrl(Environment environment) {
        return baseUrl(environment) + "/valid/api/v1/trusted-services/authentications";
    }
}
