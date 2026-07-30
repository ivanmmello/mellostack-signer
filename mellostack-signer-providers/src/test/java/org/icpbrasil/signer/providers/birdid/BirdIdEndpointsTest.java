package org.icpbrasil.signer.providers.birdid;

import org.icpbrasil.signer.model.Environment;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BirdIdEndpointsTest {

    @Test
    void homologationUsesHttpsBirdIdHost() {
        assertEquals("https://apihom.birdid.com.br", BirdIdEndpoints.baseUrl(Environment.HOMOLOGATION));
        assertTrue(BirdIdEndpoints.signatureUrl(Environment.HOMOLOGATION).startsWith("https://"));
    }

    @Test
    void productionUsesHttpsBirdIdHost() {
        assertEquals("https://api.birdid.com.br", BirdIdEndpoints.baseUrl(Environment.PRODUCTION));
    }
}
