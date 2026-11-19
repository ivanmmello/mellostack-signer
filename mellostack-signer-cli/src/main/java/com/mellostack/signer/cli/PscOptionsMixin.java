package com.mellostack.signer.cli;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.provider.PSCProvider;
import picocli.CommandLine.Option;

/**
 * Opções compartilhadas de PSC entre os subcomandos {@code sign} e {@code sign-batch}.
 */
class PscOptionsMixin {

    @Option(names = "--provider", description = "PSC: birdid, remoteid, vidaas, safeid, serproid, bry (env: PSC_PROVIDER, padrão birdid)")
    String provider;

    @Option(names = "--client-id", description = "OAuth2 client_id (env: PSC_CLIENT_ID)")
    String clientId;

    @Option(names = "--client-secret", description = "OAuth2 client_secret (env: PSC_CLIENT_SECRET)")
    String clientSecret;

    @Option(names = "--token", description = "Access token do usuário (env: PSC_USER_ACCESS_TOKEN)")
    String accessToken;

    @Option(names = "--environment", description = "homologation ou production (env: PSC_ENVIRONMENT)")
    String environment;

    @Option(names = "--certificate-alias", description = "Alias do certificado (env: PSC_CERTIFICATE_ALIAS)")
    String certificateAlias;

    @Option(names = "--api-base-url", description = "URL base da API (obrigatório para remoteid; env: PSC_API_BASE_URL)")
    String apiBaseUrl;

    @Option(names = "--reason", description = "Motivo da assinatura (env: SIGN_REASON)")
    String reason;

    @Option(names = "--location", description = "Local da assinatura (env: SIGN_LOCATION)")
    String location;

    @Option(names = "--timestamp", description = "Incluir carimbo de tempo PAdES-T")
    boolean timestamp;

    @Option(names = "--visible", description = "Assinatura visível no PDF")
    boolean visibleSignature;

    @Option(names = "--validate", description = "Executar pré-validação local DOC-ICP-15 após assinar")
    boolean validate;

    String resolveAccessToken() {
        return CliSupport.requireValue(accessToken, "PSC_USER_ACCESS_TOKEN");
    }

    PSCProvider createProvider() {
        String resolvedProvider = CliSupport.optionalValue(provider, "PSC_PROVIDER", "birdid");
        String resolvedClientId = CliSupport.requireValue(clientId, "PSC_CLIENT_ID");
        String resolvedClientSecret = CliSupport.requireValue(clientSecret, "PSC_CLIENT_SECRET");
        Environment resolvedEnvironment = CliSupport.parseEnvironment(
                CliSupport.optionalValue(environment, "PSC_ENVIRONMENT", "homologation"));
        String resolvedAlias = CliSupport.optionalValue(certificateAlias, "PSC_CERTIFICATE_ALIAS", null);
        String resolvedApiBaseUrl = CliSupport.optionalValue(apiBaseUrl, "PSC_API_BASE_URL", null);

        if ("remoteid".equalsIgnoreCase(resolvedProvider)
                || "remote-id".equalsIgnoreCase(resolvedProvider)) {
            if (resolvedApiBaseUrl == null || resolvedApiBaseUrl.isBlank()) {
                throw new IllegalArgumentException(
                        "Remote ID exige --api-base-url ou PSC_API_BASE_URL");
            }
        }

        return CliPscFactory.create(
                resolvedProvider,
                resolvedClientId,
                resolvedClientSecret,
                resolvedEnvironment,
                resolvedAlias,
                resolvedApiBaseUrl);
    }
}
