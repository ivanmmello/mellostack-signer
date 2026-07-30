package org.icpbrasil.signer.providers.safeid;

import org.icpbrasil.signer.model.Environment;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SafeIdEndpointsTest {

    @Test
    void resolvesHomologationBaseUrl() {
        assertTrue(SafeIdEndpoints.baseUrl(Environment.HOMOLOGATION)
                .startsWith("https://pscsafeweb.safewebpss.com.br"));
    }

    @Test
    void resolvesProductionBaseUrl() {
        assertEquals("https://psc.safeweb.com.br", SafeIdEndpoints.baseUrl(Environment.PRODUCTION));
    }
}
