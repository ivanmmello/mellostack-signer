package com.mellostack.signer.cli;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.birdid.BirdIdProviderBuilder;
import org.icpbrasil.signer.providers.bry.BryProviderBuilder;
import org.icpbrasil.signer.providers.remoteid.RemoteIdProviderBuilder;
import org.icpbrasil.signer.providers.safeid.SafeIdProviderBuilder;
import org.icpbrasil.signer.providers.serproid.SerproIdProviderBuilder;
import org.icpbrasil.signer.providers.vidaas.VidaasProviderBuilder;

import java.util.Locale;

final class CliPscFactory {

    private CliPscFactory() {
    }

    static PSCProvider create(String providerId, String clientId, String clientSecret,
                              Environment environment, String certificateAlias, String apiBaseUrl) {
        String normalized = providerId.toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "birdid", "bird-id" -> new BirdIdProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withEnvironment(environment)
                    .withCertificateAlias(certificateAlias)
                    .build();
            case "remoteid", "remote-id" -> new RemoteIdProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withApiBaseUrl(apiBaseUrl)
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
            case "serproid", "serpro-id" -> new SerproIdProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withEnvironment(environment)
                    .withCertificateAlias(certificateAlias)
                    .build();
            case "bry", "integra-bry" -> new BryProviderBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .withEnvironment(environment)
                    .build();
            default -> throw new IllegalArgumentException(
                    "PSC desconhecido: " + providerId + " (use birdid, remoteid, vidaas, safeid, serproid ou bry)");
        };
    }
}
