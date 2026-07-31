package org.icpbrasil.signer.core.integration;

import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;
import org.icpbrasil.signer.providers.birdid.BirdIdProviderBuilder;
import org.icpbrasil.signer.validator.SignatureValidator;
import org.icpbrasil.signer.validator.pades.PadesValidationResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.InputStream;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integração manual com PSCs em homologação — requer credenciais reais via variáveis de ambiente.
 *
 * <p>Gate de release 1.0.0 (Bird ID):
 * <pre>{@code
 * set PSC_HOMOLOGATION_ENABLED=true
 * set BIRDID_CLIENT_ID=...
 * set BIRDID_CLIENT_SECRET=...
 * set PSC_ACCESS_TOKEN=...
 * mvn -pl mellostack-signer-sdk test -Dgroups=integration -Dtest=PscHomologationIT
 * }</pre>
 */
@Tag("integration")
@EnabledIfEnvironmentVariable(named = "PSC_HOMOLOGATION_ENABLED", matches = "true")
class PscHomologationIT {

    private static byte[] samplePdf;

    @BeforeAll
    static void loadSamplePdf() throws Exception {
        try (InputStream input = PscHomologationIT.class.getResourceAsStream("/golden/sample-contract.pdf")) {
            samplePdf = Objects.requireNonNull(input, "missing golden sample-contract.pdf").readAllBytes();
        }
    }

    @Test
    void birdIdProviderCanBeConfiguredForHomologation() {
        PSCProvider provider = new BirdIdProviderBuilder()
                .withEnvironment(Environment.HOMOLOGATION)
                .withClientId(requiredEnv("BIRDID_CLIENT_ID"))
                .withClientSecret(requiredEnv("BIRDID_CLIENT_SECRET"))
                .build();

        assertNotNull(provider);
        assertNotNull(provider.getProviderId());
    }

    @Test
    void birdIdSignsPdfInHomologation() {
        PSCProvider provider = new BirdIdProviderBuilder()
                .withEnvironment(Environment.HOMOLOGATION)
                .withClientId(requiredEnv("BIRDID_CLIENT_ID"))
                .withClientSecret(requiredEnv("BIRDID_CLIENT_SECRET"))
                .withCertificateAlias(optionalEnv("BIRDID_CERTIFICATE_ALIAS"))
                .build();

        CloudSigner signer = new CloudSigner(provider);
        SignatureOptions options = SignatureOptions.builder()
                .withUserAccessToken(requiredEnv("PSC_ACCESS_TOKEN"))
                .withReason("MelloStack Signer — homologação Bird ID")
                .withLocation("Brasil")
                .withTimestamp(false)
                .withVisibleSignature(false)
                .build();

        byte[] signedPdf = signer.signPdf(samplePdf, options);
        PadesValidationResult result = SignatureValidator.validateSignedPdf(signedPdf);

        assertTrue(result.isValid(), "PAdES local validation failed: " + result);
        assertTrue(result.docIcpCompliant(), "DOC-ICP-15 policy check failed");
        assertNotNull(result.signerCertificate());
    }

    private static String requiredEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing environment variable: " + name);
        }
        return value.trim();
    }

    private static String optionalEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
