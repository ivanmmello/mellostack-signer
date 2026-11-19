package com.mellostack.signer.cli;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.validator.SignatureValidator;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
        name = "sign-batch",
        description = "Assina vários PDFs com uma única autorização PSC (batch signing)")
final class SignPdfBatchCommand implements Callable<Integer> {

    @Parameters(description = "Arquivos PDF de entrada (mínimo 1, máximo 50)")
    List<Path> inputs;

    @Option(names = {"-d", "--output-dir"}, required = true, description = "Diretório de saída dos PDFs assinados")
    Path outputDir;

    @Mixin
    PscOptionsMixin psc;

    @Override
    public Integer call() throws Exception {
        if (inputs == null || inputs.isEmpty()) {
            throw new IllegalArgumentException("Informe ao menos um PDF de entrada");
        }

        List<byte[]> pdfBytesList = new ArrayList<>(inputs.size());
        for (Path input : inputs) {
            pdfBytesList.add(CliSupport.readPdf(input));
        }

        CloudSigner signer = new CloudSigner(psc.createProvider());
        SignatureOptions options = CliSupport.buildOptions(
                psc.resolveAccessToken(),
                CliSupport.optionalValue(psc.reason, "SIGN_REASON", "Assinatura digital ICP-Brasil"),
                CliSupport.optionalValue(psc.location, "SIGN_LOCATION", "Brasil"),
                psc.timestamp,
                psc.visibleSignature);

        List<byte[]> signedPdfs = signer.signPdfBatch(pdfBytesList, options);

        boolean allValid = true;
        for (int i = 0; i < inputs.size(); i++) {
            Path output = outputDir.resolve(inputs.get(i).getFileName());
            CliSupport.writePdf(output, signedPdfs.get(i));
            System.out.println("Assinado: " + output.toAbsolutePath());

            if (psc.validate) {
                boolean valid = SignatureValidator.isSignedPdfValid(signedPdfs.get(i));
                System.out.println("  Pré-validação DOC-ICP-15: " + (valid ? "OK" : "FALHOU"));
                allValid &= valid;
            }
        }

        System.out.println("Lote concluído: " + signedPdfs.size() + " documento(s)");
        if (psc.validate && !allValid) {
            return 2;
        }
        return 0;
    }
}
