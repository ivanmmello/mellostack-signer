package org.icpbrasil.signer.providers.serproid;

import org.icpbrasil.signer.model.Environment;

/**
 * Endpoints SerproID por ambiente.
 *
 * <p>A base inclui {@code /oauth} porque o PSC publica {@code /oauth/v0/oauth/*}.
 *
 * @see <a href="https://serproid.serpro.gov.br/manual-integracao/">Manual de integração SerproID</a>
 */
public final class SerproIdEndpoints {

    private static final String PRODUCTION_BASE = "https://serproid.serpro.gov.br/oauth";
    private static final String HOMOLOGATION_BASE = "https://hom.serproid.serpro.gov.br/oauth";

    /** Limite atual do array {@code hashes} na API de assinatura. */
    public static final int MAX_HASHES_PER_REQUEST = 5;

    private SerproIdEndpoints() {
    }

    public static String baseUrl(Environment environment) {
        return switch (environment) {
            case PRODUCTION -> PRODUCTION_BASE;
            case HOMOLOGATION -> HOMOLOGATION_BASE;
        };
    }
}
