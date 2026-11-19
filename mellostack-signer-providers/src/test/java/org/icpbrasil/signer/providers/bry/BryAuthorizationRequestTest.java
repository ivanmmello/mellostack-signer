package org.icpbrasil.signer.providers.bry;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BryAuthorizationRequestTest {

    @Test
    void rejectsVidaasBatchAboveTwentyWithoutSignatureSession() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () ->
                BryAuthorizationRequest.builder()
                        .psc(BryPsc.VIDAAS)
                        .redirectUri("https://app.example/callback")
                        .state("session-1")
                        .numberOfDocuments(21)
                        .scope(BrySignatureScope.MULTI_SIGNATURE)
                        .build());

        assertEquals("VIDaaS requests above 20 documents require scope signature_session", error.getMessage());
    }

    @Test
    void rejectsCpfTogetherWithCnpj() {
        assertThrows(IllegalArgumentException.class, () ->
                BryAuthorizationRequest.builder()
                        .psc(BryPsc.BIRD_ID)
                        .redirectUri("https://app.example/callback")
                        .state("session-1")
                        .cpf("12345678909")
                        .cnpj("12345678000199")
                        .build());
    }
}
