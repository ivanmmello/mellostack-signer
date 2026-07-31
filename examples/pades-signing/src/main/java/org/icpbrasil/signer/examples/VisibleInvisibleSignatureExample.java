package org.icpbrasil.signer.examples;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;

import java.nio.file.Path;

/**
 * Demonstra assinatura invisível (apenas metadados PKCS#7) vs. visível (campo de assinatura no PDF).
 * <p>
 * Gera dois arquivos a partir do mesmo PDF de entrada — útil para comparar apresentação no leitor PDF.
 */
public final class VisibleInvisibleSignatureExample {

    public static void main(String[] args) throws Exception {
        ExampleSupport.printUsage(
                "VisibleInvisibleSignatureExample",
                "Assina o mesmo PDF duas vezes: uma invisível e outra com campo visível.",
                "PSC_CLIENT_ID",
                "PSC_CLIENT_SECRET",
                "PSC_USER_ACCESS_TOKEN");

        String accessToken = ExampleSupport.requireEnv("PSC_USER_ACCESS_TOKEN");
        byte[] pdfBytes = ExampleSupport.loadPdf(ExampleSupport.DEFAULT_PDF_RESOURCE);
        CloudSigner signer = new CloudSigner(PscProviderFactory.createFromEnvironment());

        SignatureOptions invisible = SignatureOptions.builder()
                .withUserAccessToken(accessToken)
                .withReason("Assinatura invisível — auditoria")
                .withLocation(ExampleSupport.optionalEnv("SIGN_LOCATION", "Brasil"))
                .withTimestamp(false)
                .withVisibleSignature(false)
                .build();

        SignatureOptions visible = SignatureOptions.builder()
                .withUserAccessToken(accessToken)
                .withReason("Assinatura visível — contrato")
                .withLocation(ExampleSupport.optionalEnv("SIGN_LOCATION", "Brasil"))
                .withTimestamp(false)
                .withVisibleSignature(true)
                .build();

        byte[] invisiblePdf = signer.signPdf(pdfBytes, invisible);
        byte[] visiblePdf = signer.signPdf(pdfBytes, visible);

        Path invisibleOutput = Path.of(
                ExampleSupport.optionalEnv("OUTPUT_PDF_INVISIBLE", "signed-invisible.pdf"));
        Path visibleOutput = Path.of(
                ExampleSupport.optionalEnv("OUTPUT_PDF_VISIBLE", "signed-visible.pdf"));

        ExampleSupport.writePdf(invisibleOutput, invisiblePdf);
        ExampleSupport.writePdf(visibleOutput, visiblePdf);

        System.out.println("Assinatura invisível: " + invisibleOutput.toAbsolutePath());
        System.out.println("Assinatura visível:   " + visibleOutput.toAbsolutePath());
    }

    private VisibleInvisibleSignatureExample() {
    }
}
