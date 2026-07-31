package org.icpbrasil.signer.examples;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.validator.SignatureValidator;
import org.icpbrasil.signer.validator.act.ActClientConfig;
import org.icpbrasil.signer.validator.act.Rfc3161TimestampAuthority;

import java.nio.file.Path;

/**
 * Exemplo PAdES-T: assinatura com carimbo do tempo (ACT RFC 3161).
 * <p>
 * A URL da ACT é definida pela aplicação host — o SDK não embute endpoints de timestamp.
 */
public final class TimestampSigningExample {

    public static void main(String[] args) throws Exception {
        ExampleSupport.printUsage(
                "TimestampSigningExample",
                "Assina PDF com PAdES-T (CMS + token de timestamp da ACT).",
                "PSC_CLIENT_ID",
                "PSC_CLIENT_SECRET",
                "PSC_USER_ACCESS_TOKEN",
                "ACT_TSA_URL (HTTPS da ACT)");

        String accessToken = ExampleSupport.requireEnv("PSC_USER_ACCESS_TOKEN");
        String tsaUrl = ExampleSupport.requireEnv("ACT_TSA_URL");

        var timestampAuthority = new Rfc3161TimestampAuthority(ActClientConfig.of(tsaUrl));
        CloudSigner signer = new CloudSigner(
                PscProviderFactory.createFromEnvironment(),
                timestampAuthority);

        byte[] pdfBytes = ExampleSupport.loadPdf(ExampleSupport.DEFAULT_PDF_RESOURCE);
        SignatureOptions options = SignatureOptions.builder()
                .withUserAccessToken(accessToken)
                .withReason(ExampleSupport.optionalEnv("SIGN_REASON", "Assinatura com carimbo do tempo"))
                .withLocation(ExampleSupport.optionalEnv("SIGN_LOCATION", "Brasil"))
                .withTimestamp(true)
                .withVisibleSignature(false)
                .build();

        byte[] signedPdf = signer.signPdf(pdfBytes, options);
        Path output = ExampleSupport.resolveOutputPath("signed-with-timestamp.pdf");
        ExampleSupport.writePdf(output, signedPdf);

        System.out.println("ACT: " + tsaUrl);
        System.out.println("PDF PAdES-T gravado em: " + output.toAbsolutePath());
        System.out.println("Pré-validação local: "
                + (SignatureValidator.isSignedPdfValid(signedPdf) ? "OK" : "FALHOU"));
    }

    private TimestampSigningExample() {
    }
}
