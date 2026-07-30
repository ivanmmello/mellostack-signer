package org.icpbrasil.signer.providers.vidaas;

import org.icpbrasil.signer.model.Environment;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VidaasEndpointsTest {

    @Test
    void resolvesHomologationBaseUrl() {
        assertEquals("https://hml-certificado.vidaas.com.br", VidaasEndpoints.baseUrl(Environment.HOMOLOGATION));
    }

    @Test
    void resolvesProductionBaseUrl() {
        assertEquals("https://certificado.vidaas.com.br", VidaasEndpoints.baseUrl(Environment.PRODUCTION));
    }

    @Test
    void pushAuthenticationsUrlIncludesPath() {
        assertTrue(VidaasEndpoints.pushAuthenticationsUrl(Environment.HOMOLOGATION)
                .endsWith("/valid/api/v1/trusted-services/authentications"));
    }
}
