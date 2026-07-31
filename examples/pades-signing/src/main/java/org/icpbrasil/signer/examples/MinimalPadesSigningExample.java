package org.icpbrasil.signer.examples;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.validator.SignatureValidator;

import java.nio.file.Path;

/**
 * Exemplo mínimo: assinatura PAdES em nuvem com qualquer PSC configurado via ambiente.
 * <p>
 * O PDF de entrada permanece local — apenas o hash SHA-256 do ByteRange é enviado ao PSC.
 */
public final class MinimalPadesSigningExample {

    public static void main(String[] args) throws Exception {
        ExampleSupport.printUsage(
                "MinimalPadesSigningExample",
                "Assina o PDF de exemplo (ou INPUT_PDF) com o PSC definido em PSC_PROVIDER.",
                "PSC_CLIENT_ID",
                "PSC_CLIENT_SECRET",
                "PSC_USER_ACCESS_TOKEN",
                "PSC_PROVIDER (padrão: birdid)",
                "PSC_API_BASE_URL (obrigatório para remoteid)");

        String accessToken = ExampleSupport.requireEnv("PSC_USER_ACCESS_TOKEN");
        byte[] pdfBytes = loadInputPdf();
        CloudSigner signer = new CloudSigner(PscProviderFactory.createFromEnvironment());

        SignatureOptions options = ExampleSupport.baseOptions(accessToken);
        byte[] signedPdf = signer.signPdf(pdfBytes, options);

        Path output = ExampleSupport.resolveOutputPath("signed-minimal.pdf");
        ExampleSupport.writePdf(output, signedPdf);

        boolean valid = SignatureValidator.isSignedPdfValid(signedPdf);
        System.out.println("PDF assinado gravado em: " + output.toAbsolutePath());
        System.out.println("Pré-validação local DOC-ICP-15: " + (valid ? "OK" : "FALHOU"));
    }

    private static byte[] loadInputPdf() throws Exception {
        String inputPath = System.getenv("INPUT_PDF");
        if (inputPath != null && !inputPath.isBlank()) {
            return ExampleSupport.loadPdf(Path.of(inputPath.trim()));
        }
        return ExampleSupport.loadPdf(ExampleSupport.DEFAULT_PDF_RESOURCE);
    }

    private MinimalPadesSigningExample() {
    }
}
