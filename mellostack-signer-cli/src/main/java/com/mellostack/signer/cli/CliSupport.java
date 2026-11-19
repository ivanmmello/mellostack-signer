package com.mellostack.signer.cli;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

final class CliSupport {

    private CliSupport() {
    }

    static String requireValue(String flagValue, String envName) {
        if (flagValue != null && !flagValue.isBlank()) {
            return flagValue.trim();
        }
        String env = System.getenv(envName);
        if (env == null || env.isBlank()) {
            throw new IllegalArgumentException(
                    "Informe --" + envName.toLowerCase(Locale.ROOT).replace('_', '-')
                            + " ou defina a variável de ambiente " + envName);
        }
        return env.trim();
    }

    static String optionalValue(String flagValue, String envName, String defaultValue) {
        if (flagValue != null && !flagValue.isBlank()) {
            return flagValue.trim();
        }
        String env = System.getenv(envName);
        if (env == null || env.isBlank()) {
            return defaultValue;
        }
        return env.trim();
    }

    static Environment parseEnvironment(String raw) {
        if (raw == null || raw.isBlank()) {
            return Environment.HOMOLOGATION;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "production", "prod" -> Environment.PRODUCTION;
            case "homologation", "homologacao", "hml", "sandbox" -> Environment.HOMOLOGATION;
            default -> throw new IllegalArgumentException(
                    "Ambiente inválido: " + raw + " (use homologation ou production)");
        };
    }

    static byte[] readPdf(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Arquivo PDF não encontrado: " + path);
        }
        return Files.readAllBytes(path);
    }

    static void writePdf(Path output, byte[] pdfBytes) throws IOException {
        Path parent = output.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(output, pdfBytes);
    }

    static SignatureOptions buildOptions(String accessToken, String reason, String location,
                                         boolean timestamp, boolean visibleSignature) {
        return SignatureOptions.builder()
                .withUserAccessToken(accessToken)
                .withReason(reason)
                .withLocation(location)
                .withTimestamp(timestamp)
                .withVisibleSignature(visibleSignature)
                .build();
    }
}
