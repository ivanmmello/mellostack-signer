package org.icpbrasil.signer.examples;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.providers.birdid.BirdIdProviderBuilder;
import org.icpbrasil.signer.validator.SignatureValidator;

import java.nio.file.Path;

/**
 * Exemplo Bird ID: configuração explícita do driver e assinatura de contrato PDF.
 * <p>
 * Fluxo OAuth2 do usuário (authorization code + PKCE) ocorre fora deste exemplo —
 * a aplicação host obtém {@code PSC_USER_ACCESS_TOKEN} após o redirect do Bird ID.
 *
 * @see org.icpbrasil.signer.providers.birdid.BirdIdOAuth2Support
 */
public final class BirdIdContractSigningExample {

    public static void main(String[] args) throws Exception {
        ExampleSupport.printUsage(
                "BirdIdContractSigningExample",
                "Assina um contrato PDF usando BirdIdProviderBuilder em homologação ou produção.",
                "PSC_CLIENT_ID",
                "PSC_CLIENT_SECRET",
                "PSC_USER_ACCESS_TOKEN");

        Environment environment = ExampleSupport.parseEnvironment(
                ExampleSupport.optionalEnv("PSC_ENVIRONMENT", "homologation"));
        String certificateAlias = System.getenv("PSC_CERTIFICATE_ALIAS");

        var birdIdProvider = new BirdIdProviderBuilder()
                .withClientId(ExampleSupport.requireEnv("PSC_CLIENT_ID"))
                .withClientSecret(ExampleSupport.requireEnv("PSC_CLIENT_SECRET"))
                .withEnvironment(environment)
                .withCertificateAlias(certificateAlias)
                .build();

        CloudSigner signer = new CloudSigner(birdIdProvider);
        byte[] contractPdf = ExampleSupport.loadPdf(ExampleSupport.DEFAULT_PDF_RESOURCE);

        SignatureOptions options = SignatureOptions.builder()
                .withUserAccessToken(ExampleSupport.requireEnv("PSC_USER_ACCESS_TOKEN"))
                .withReason("Assinatura do Contrato de Prestação de Serviços")
                .withLocation(ExampleSupport.optionalEnv("SIGN_LOCATION", "São Paulo - SP"))
                .withTimestamp(false)
                .withVisibleSignature(false)
                .build();

        byte[] signedContract = signer.signPdf(contractPdf, options);
        Path output = ExampleSupport.resolveOutputPath("signed-contract-birdid.pdf");
        ExampleSupport.writePdf(output, signedContract);

        System.out.println("PSC: Bird ID (" + environment + ")");
        System.out.println("PDF assinado gravado em: " + output.toAbsolutePath());
        System.out.println("Pré-validação local: "
                + (SignatureValidator.isSignedPdfValid(signedContract) ? "OK" : "FALHOU"));
    }

    private BirdIdContractSigningExample() {
    }
}
