package org.icpbrasil.signer.providers.bry;

import org.icpbrasil.signer.model.Environment;

/**
 * Endpoints da Integra Bry e do HUB Signer.
 *
 * @see <a href="https://bry-developer.readme.io/reference/integra-bry">Integra Bry</a>
 */
public final class BryEndpoints {

    private BryEndpoints() {
    }

    public static String cloudTokenUrl(Environment environment) {
        return switch (environment) {
            case PRODUCTION -> "https://cloud.bry.com.br/token-service/jwt";
            case HOMOLOGATION -> "https://cloud-hom.bry.com.br/token-service/jwt";
        };
    }

    public static String integraBaseUrl(Environment environment) {
        return switch (environment) {
            case PRODUCTION -> "https://integra.bry.com.br/api/service";
            case HOMOLOGATION -> "https://integra.hom.bry.com.br/api/service";
        };
    }

    public static String hubBaseUrl(Environment environment) {
        return switch (environment) {
            case PRODUCTION -> "https://hub2.bry.com.br/fw/v1";
            case HOMOLOGATION -> "https://hub2.hom.bry.com.br/fw/v1";
        };
    }

    public static String pscLinkUrl(Environment environment) {
        return integraBaseUrl(environment) + "/psc/link";
    }

    public static String certificateUrl(Environment environment) {
        return integraBaseUrl(environment) + "/auth/certificate";
    }

    public static String cmsSignatureUrl(Environment environment) {
        return hubBaseUrl(environment) + "/cms/kms/assinaturas";
    }
}
