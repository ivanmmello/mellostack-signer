package org.icpbrasil.signer.core.integration;

import org.icpbrasil.signer.core.crypto.EncodingUtils;
import org.icpbrasil.signer.core.pdf.PadesPrepareOptions;
import org.icpbrasil.signer.core.pdf.PadesSignaturePreparer;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Gera o hash de referência do golden PDF (executar manualmente ao alterar o PDF).
 */
class GoldenHashGenerator {

    @Test
    @Disabled("Utilitário manual — executar ao alterar golden/sample-contract.pdf")
    void writeGoldenDocumentHash() throws Exception {
        try (InputStream input = GoldenHashGenerator.class.getResourceAsStream("/golden/sample-contract.pdf")) {
            byte[] goldenPdf = Objects.requireNonNull(input).readAllBytes();
            var prepared = new PadesSignaturePreparer().prepare(
                    goldenPdf,
                    PadesPrepareOptions.builder().build()
            );
            String hex = EncodingUtils.toHex(prepared.getDocumentHash());
            Path output = Path.of("src/test/resources/golden/sample-contract.document-hash.hex");
            Files.writeString(output, hex);
        }
    }
}
