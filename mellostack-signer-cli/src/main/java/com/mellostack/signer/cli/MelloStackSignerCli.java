package com.mellostack.signer.cli;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.icpbrasil.signer.SignerSdk;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.security.Security;
import java.util.concurrent.Callable;

/**
 * Ponto de entrada da CLI MelloStack Signer — assinatura PAdES ICP-Brasil em nuvem.
 */
@Command(
        name = "mellostack-signer",
        mixinStandardHelpOptions = true,
        version = SignerSdk.VERSION,
        description = "Assina PDFs com certificado em nuvem (PAdES ICP-Brasil V12)",
        subcommands = {
                SignPdfCommand.class,
                SignPdfBatchCommand.class
        })
public final class MelloStackSignerCli implements Callable<Integer> {

    public static void main(String[] args) {
        registerSecurityProviders();
        int exitCode = new CommandLine(new MelloStackSignerCli()).execute(args);
        System.exit(exitCode);
    }

    static void registerSecurityProviders() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public Integer call() {
        CommandLine.usage(this, System.out);
        return CommandLine.ExitCode.USAGE;
    }
}
