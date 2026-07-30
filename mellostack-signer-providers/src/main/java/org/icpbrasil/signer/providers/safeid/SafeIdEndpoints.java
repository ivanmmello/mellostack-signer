package org.icpbrasil.signer.providers.safeid;

import org.icpbrasil.signer.model.Environment;

/**
 * Endpoints SafeID (Safeweb PSC) por ambiente.
 *
 * @see <a href="https://repositorio.acsafeweb.com.br/psc-safeweb/ro-psc-safeweb.pdf">PSC Safeweb RO</a>
 */
public final class SafeIdEndpoints {

    private static final String PRODUCTION_BASE = "https://psc.safeweb.com.br";
    private static final String HOMOLOGATION_BASE =
            "https://pscsafeweb.safewebpss.com.br/Service/Microservice/OAuth/api";

    private SafeIdEndpoints() {
    }

    public static String baseUrl(Environment environment) {
        return switch (environment) {
            case PRODUCTION -> PRODUCTION_BASE;
            case HOMOLOGATION -> HOMOLOGATION_BASE;
        };
    }
}
