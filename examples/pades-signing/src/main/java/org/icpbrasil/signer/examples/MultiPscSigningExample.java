package org.icpbrasil.signer.examples;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;

import java.nio.file.Path;

/**
 * Alternância entre PSCs sem alterar regra de negócio: apenas troca-se o {@link PSCProvider}
 * passado ao {@link CloudSigner}.
 * <p>
 * Execute duas vezes alterando {@code PSC_PROVIDER} (birdid, remoteid, vidaas, safeid).
 */
public final class MultiPscSigningExample {

    public static void main(String[] args) throws Exception {
        ExampleSupport.printUsage(
                "MultiPscSigningExample",
                "Mesmo fluxo de assinatura com PSC selecionado por PSC_PROVIDER.",
                "PSC_PROVIDER (birdid | remoteid | vidaas | safeid)",
                "PSC_CLIENT_ID",
                "PSC_CLIENT_SECRET",
                "PSC_USER_ACCESS_TOKEN",
                "PSC_API_BASE_URL (remoteid)");

        PSCProvider provider = PscProviderFactory.createFromEnvironment();
        CloudSigner signer = new CloudSigner(provider);

        byte[] pdfBytes = ExampleSupport.loadPdf(ExampleSupport.DEFAULT_PDF_RESOURCE);
        SignatureOptions options = ExampleSupport.baseOptions(
                ExampleSupport.requireEnv("PSC_USER_ACCESS_TOKEN"));

        byte[] signedPdf = signer.signPdf(pdfBytes, options);
        String fileName = "signed-" + provider.getProviderId() + ".pdf";
        Path output = ExampleSupport.resolveOutputPath(fileName);
        ExampleSupport.writePdf(output, signedPdf);

        System.out.println("PSC ativo: " + provider.getProviderId()
                + " (" + provider.getEnvironment() + ")");
        System.out.println("PDF assinado gravado em: " + output.toAbsolutePath());
        System.out.println();
        System.out.println("Para alternar PSC, reexecute com outro PSC_PROVIDER — "
                + "o código de assinatura permanece idêntico.");
    }

    private MultiPscSigningExample() {
    }
}
