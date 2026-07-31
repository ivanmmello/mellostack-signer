package org.icpbrasil.signer.examples;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Utilitários compartilhados pelos exemplos executáveis (leitura de env, PDF e saída).
 */
public final class ExampleSupport {

    public static final String DEFAULT_PDF_RESOURCE = "/sample-contract.pdf";

    private ExampleSupport() {
    }

    public static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Defina a variável de ambiente " + name);
        }
        return value.trim();
    }

    public static String optionalEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return value.trim();
    }

    public static Environment parseEnvironment(String raw) {
        if (raw == null || raw.isBlank()) {
            return Environment.HOMOLOGATION;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "production", "prod" -> Environment.PRODUCTION;
            case "homologation", "homologacao", "hml", "sandbox" -> Environment.HOMOLOGATION;
            default -> throw new IllegalArgumentException(
                    "PSC_ENVIRONMENT inválido: " + raw + " (use homologation ou production)");
        };
    }

    public static byte[] loadPdf(String resourcePath) throws IOException {
        try (InputStream in = ExampleSupport.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException("Recurso não encontrado no classpath: " + resourcePath);
            }
            return in.readAllBytes();
        }
    }

    public static byte[] loadPdf(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Arquivo PDF não encontrado: " + path);
        }
        return Files.readAllBytes(path);
    }

    public static Path resolveOutputPath(String defaultFileName) {
        String configured = System.getenv("OUTPUT_PDF");
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured.trim());
        }
        return Path.of(defaultFileName);
    }

    public static void writePdf(Path output, byte[] pdfBytes) throws IOException {
        Path parent = output.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(output, pdfBytes);
    }

    public static SignatureOptions baseOptions(String accessToken) {
        return SignatureOptions.builder()
                .withUserAccessToken(accessToken)
                .withReason(optionalEnv("SIGN_REASON", "Assinatura digital ICP-Brasil"))
                .withLocation(optionalEnv("SIGN_LOCATION", "Brasil"))
                .withTimestamp(false)
                .withVisibleSignature(false)
                .build();
    }

    public static void printUsage(String exampleName, String description, String... envVars) {
        System.out.println("=== " + exampleName + " ===");
        System.out.println(description);
        System.out.println();
        System.out.println("Variáveis de ambiente:");
        for (String envVar : envVars) {
            System.out.println("  - " + envVar);
        }
        System.out.println();
        System.out.println("Opcionais: PSC_ENVIRONMENT, SIGN_REASON, SIGN_LOCATION, OUTPUT_PDF, PSC_CERTIFICATE_ALIAS");
    }
}
