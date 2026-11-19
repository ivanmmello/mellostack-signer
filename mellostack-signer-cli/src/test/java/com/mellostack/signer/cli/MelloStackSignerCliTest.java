package com.mellostack.signer.cli;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MelloStackSignerCliTest {

    @Test
    void printsUsageWhenNoSubcommand() {
        CommandLine cmd = new CommandLine(new MelloStackSignerCli());
        int exit = cmd.execute();
        assertEquals(CommandLine.ExitCode.USAGE, exit);
    }

    @Test
    void signRequiresOutputOption() {
        CommandLine cmd = new CommandLine(new MelloStackSignerCli());
        int exit = cmd.execute("sign", "input.pdf");
        assertEquals(CommandLine.ExitCode.USAGE, exit);
    }

    @Test
    void signBatchRequiresOutputDir() {
        CommandLine cmd = new CommandLine(new MelloStackSignerCli());
        int exit = cmd.execute("sign-batch", "a.pdf", "b.pdf");
        assertEquals(CommandLine.ExitCode.USAGE, exit);
    }

    @Test
    void versionOptionWorks() {
        CommandLine cmd = new CommandLine(new MelloStackSignerCli());
        int exit = cmd.execute("--version");
        assertEquals(CommandLine.ExitCode.OK, exit);
    }

    @Test
    void cliPscFactoryRejectsUnknownProvider() {
        IllegalArgumentException ex = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> CliPscFactory.create(
                        "unknown",
                        "id",
                        "secret",
                        org.icpbrasil.signer.model.Environment.HOMOLOGATION,
                        null,
                        null));
        assertTrue(ex.getMessage().contains("unknown"));
    }
}
