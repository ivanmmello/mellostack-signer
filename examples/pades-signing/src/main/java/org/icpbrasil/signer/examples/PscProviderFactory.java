package org.icpbrasil.signer.examples;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.birdid.BirdIdProviderBuilder;
import org.icpbrasil.signer.providers.remoteid.RemoteIdProviderBuilder;
import org.icpbrasil.signer.providers.safeid.SafeIdProviderBuilder;
import org.icpbrasil.signer.providers.vidaas.VidaasProviderBuilder;

import java.util.Locale;

/**
 * Cria o driver PSC a partir de variáveis de ambiente — permite alternar PSC sem mudar a regra de negócio.
 */
public final class PscProviderFactory {

    private PscProviderFactory() {
    }

    /**
     * Lê {@code PSC_PROVIDER} (birdid, remoteid, vidaas, safeid) e credenciais comuns.
     */
    public static PSCProvider createFromEnvironment() {
        String providerId = ExampleSupport.optionalEnv("PSC_PROVIDER", "birdid").toLowerCase(Locale.ROOT);
        Environment environment = ExampleSupport.parseEnvironment(
                ExampleSupport.optionalEnv("PSC_ENVIRONMENT", "homologation"));
        String clientId = ExampleSupport.requireEnv("PSC_CLIENT_ID");
        String clientSecret = ExampleSupport.requireEnv("PSC_CLIENT_SECRET");
        String certificateAlias = System.getenv("PSC_CERTIFICATE_ALIAS");

        return switch (providerId) {
            case "birdid", "bird-id" -> new BirdIdProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withEnvironment(environment)
                    .withCertificateAlias(certificateAlias)
                    .build();
            case "remoteid", "remote-id" -> new RemoteIdProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withApiBaseUrl(ExampleSupport.requireEnv("PSC_API_BASE_URL"))
                    .withEnvironment(environment)
                    .withCertificateAlias(certificateAlias)
                    .build();
            case "vidaas" -> new VidaasProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withEnvironment(environment)
                    .withCertificateAlias(certificateAlias)
                    .build();
            case "safeid", "safe-id" -> new SafeIdProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withEnvironment(environment)
                    .withCertificateAlias(certificateAlias)
                    .build();
            default -> throw new IllegalArgumentException(
                    "PSC_PROVIDER desconhecido: " + providerId
                            + " (use birdid, remoteid, vidaas ou safeid)");
        };
    }
}
