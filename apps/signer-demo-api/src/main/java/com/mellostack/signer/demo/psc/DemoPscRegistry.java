package com.mellostack.signer.demo.psc;

import com.mellostack.signer.demo.config.DemoProperties;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.birdid.BirdIdProvider;
import org.icpbrasil.signer.providers.birdid.BirdIdProviderBuilder;
import org.icpbrasil.signer.providers.oauth.OAuth2PkceGenerator;
import org.icpbrasil.signer.providers.oauth.OAuth2TokenClient;
import org.icpbrasil.signer.providers.remoteid.RemoteIdProvider;
import org.icpbrasil.signer.providers.remoteid.RemoteIdProviderBuilder;
import org.icpbrasil.signer.providers.safeid.SafeIdProvider;
import org.icpbrasil.signer.providers.safeid.SafeIdProviderBuilder;
import org.icpbrasil.signer.providers.vidaas.VidaasProvider;
import org.icpbrasil.signer.providers.vidaas.VidaasProviderBuilder;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
public class DemoPscRegistry {

    private final DemoProperties properties;

    public DemoPscRegistry(DemoProperties properties) {
        this.properties = properties;
    }

    public DemoPscBundle bundleForSession(String providerId, Environment environment) {
        DemoProperties.Psc defaults = properties.psc();
        String resolvedProvider = providerId != null && !providerId.isBlank()
                ? providerId
                : defaults.provider();
        Environment resolvedEnvironment = environment != null ? environment : parseEnvironment(defaults.environment());
        String clientId = require(defaults.clientId(), "PSC_CLIENT_ID");
        String clientSecret = require(defaults.clientSecret(), "PSC_CLIENT_SECRET");

        return switch (resolvedProvider.toLowerCase(Locale.ROOT)) {
            case "birdid", "bird-id" -> {
                BirdIdProvider provider = (BirdIdProvider) new BirdIdProviderBuilder()
                        .withClientId(clientId)
                        .withClientSecret(clientSecret)
                        .withEnvironment(resolvedEnvironment)
                        .withCertificateAlias(blankToNull(defaults.certificateAlias()))
                        .build();
                yield bundle(resolvedProvider, resolvedEnvironment, provider, wrap(provider.oauth2()));
            }
            case "remoteid", "remote-id" -> {
                RemoteIdProvider provider = (RemoteIdProvider) new RemoteIdProviderBuilder()
                        .withClientId(clientId)
                        .withClientSecret(clientSecret)
                        .withApiBaseUrl(require(defaults.apiBaseUrl(), "PSC_API_BASE_URL"))
                        .withEnvironment(resolvedEnvironment)
                        .withCertificateAlias(blankToNull(defaults.certificateAlias()))
                        .build();
                yield bundle(resolvedProvider, resolvedEnvironment, provider, wrap(provider.oauth2()));
            }
            case "vidaas" -> {
                VidaasProvider provider = (VidaasProvider) new VidaasProviderBuilder()
                        .withClientId(clientId)
                        .withClientSecret(clientSecret)
                        .withEnvironment(resolvedEnvironment)
                        .withCertificateAlias(blankToNull(defaults.certificateAlias()))
                        .build();
                yield bundle(resolvedProvider, resolvedEnvironment, provider, wrap(provider.oauth2()));
            }
            case "safeid", "safe-id" -> {
                SafeIdProvider provider = (SafeIdProvider) new SafeIdProviderBuilder()
                        .withClientId(clientId)
                        .withClientSecret(clientSecret)
                        .withEnvironment(resolvedEnvironment)
                        .withCertificateAlias(blankToNull(defaults.certificateAlias()))
                        .build();
                yield bundle(resolvedProvider, resolvedEnvironment, provider, wrap(provider.oauth2()));
            }
            default -> throw new IllegalArgumentException("Unsupported PSC provider: " + resolvedProvider);
        };
    }

    private static DemoPscBundle bundle(
            String providerId,
            Environment environment,
            PSCProvider provider,
            DemoOAuthSupport oauth) {
        return new DemoPscBundle(providerId, environment, provider, oauth);
    }

    private static DemoOAuthSupport wrap(org.icpbrasil.signer.providers.birdid.BirdIdOAuth2Support oauth) {
        return new DemoOAuthSupport(
                oauth::generatePkceChallenge,
                oauth::buildAuthorizationUrl,
                oauth::tokenClient,
                oauth::clientId,
                oauth::clientSecret);
    }

    private static DemoOAuthSupport wrap(org.icpbrasil.signer.providers.remoteid.RemoteIdOAuth2Support oauth) {
        return new DemoOAuthSupport(
                oauth::generatePkceChallenge,
                oauth::buildAuthorizationUrl,
                oauth::tokenClient,
                oauth::clientId,
                oauth::clientSecret);
    }

    private static DemoOAuthSupport wrap(org.icpbrasil.signer.providers.vidaas.VidaasOAuth2Support oauth) {
        return new DemoOAuthSupport(
                oauth::generatePkceChallenge,
                (pkce, redirectUri, state) -> oauth.buildAuthorizationUrl(pkce, redirectUri, state),
                oauth::tokenClient,
                oauth::clientId,
                oauth::clientSecret);
    }

    private static DemoOAuthSupport wrap(org.icpbrasil.signer.providers.safeid.SafeIdOAuth2Support oauth) {
        return new DemoOAuthSupport(
                oauth::generatePkceChallenge,
                oauth::buildAuthorizationUrl,
                oauth::tokenClient,
                oauth::clientId,
                oauth::clientSecret);
    }

    private static Environment parseEnvironment(String raw) {
        if (raw == null || raw.isBlank()) {
            return Environment.HOMOLOGATION;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "production", "prod" -> Environment.PRODUCTION;
            default -> Environment.HOMOLOGATION;
        };
    }

    private static String require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Configure " + name + " for the demo API");
        }
        return value.trim();
    }

    private static String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    public record DemoPscBundle(
            String providerId,
            Environment environment,
            PSCProvider provider,
            DemoOAuthSupport oauth) {
    }

    public record DemoOAuthSupport(
            PkceFactory pkceFactory,
            AuthorizationUrlBuilder authorizationUrlBuilder,
            TokenClientFactory tokenClientFactory,
            ClientIdSupplier clientIdSupplier,
            ClientSecretSupplier clientSecretSupplier) {

        public OAuth2PkceGenerator.PkceChallenge generatePkceChallenge() {
            return pkceFactory.create();
        }

        public String buildAuthorizationUrl(OAuth2PkceGenerator.PkceChallenge pkce, String redirectUri, String state) {
            return authorizationUrlBuilder.build(pkce, redirectUri, state);
        }

        public OAuth2TokenClient tokenClient() {
            return tokenClientFactory.create();
        }

        public String clientId() {
            return clientIdSupplier.get();
        }

        public String clientSecret() {
            return clientSecretSupplier.get();
        }

        @FunctionalInterface
        interface PkceFactory {
            OAuth2PkceGenerator.PkceChallenge create();
        }

        @FunctionalInterface
        interface AuthorizationUrlBuilder {
            String build(OAuth2PkceGenerator.PkceChallenge pkce, String redirectUri, String state);
        }

        @FunctionalInterface
        interface TokenClientFactory {
            OAuth2TokenClient create();
        }

        @FunctionalInterface
        interface ClientIdSupplier {
            String get();
        }

        @FunctionalInterface
        interface ClientSecretSupplier {
            String get();
        }
    }
}
