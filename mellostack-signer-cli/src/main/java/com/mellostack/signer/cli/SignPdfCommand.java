package com.mellostack.signer.cli;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.validator.SignatureValidator;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = "sign",
        description = "Assina um PDF com certificado em nuvem (PAdES ICP-Brasil)")
final class SignPdfCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Arquivo PDF de entrada")
    Path input;

    @Option(names = {"-o", "--output"}, required = true, description = "Arquivo PDF assinado de saída")
    Path output;

    @Mixin
    PscOptionsMixin psc;

    @Override
    public Integer call() throws Exception {
        byte[] pdfBytes = CliSupport.readPdf(input);
        CloudSigner signer = new CloudSigner(psc.createProvider());

        SignatureOptions options = CliSupport.buildOptions(
                psc.resolveAccessToken(),
                CliSupport.optionalValue(psc.reason, "SIGN_REASON", "Assinatura digital ICP-Brasil"),
                CliSupport.optionalValue(psc.location, "SIGN_LOCATION", "Brasil"),
                psc.timestamp,
                psc.visibleSignature);

        byte[] signedPdf = signer.signPdf(pdfBytes, options);
        CliSupport.writePdf(output, signedPdf);

        System.out.println("PDF assinado gravado em: " + output.toAbsolutePath());

        if (psc.validate) {
            boolean valid = SignatureValidator.isSignedPdfValid(signedPdf);
            System.out.println("Pré-validação local DOC-ICP-15: " + (valid ? "OK" : "FALHOU"));
            if (!valid) {
                return 2;
            }
        }

        return 0;
    }
}
