package org.icpbrasil.signer.core;

import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.provider.PSCProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CloudSignerTest {

    @Test
    void rejectsNullProvider() {
        assertThrows(IllegalArgumentException.class, () -> new CloudSigner(null));
    }

    @Test
    void signPdfNotYetImplemented() {
        var options = SignatureOptions.builder()
                .withUserAccessToken("token")
                .build();

        var signer = new CloudSigner(new PSCProvider() {
            @Override
            public String getProviderId() {
                return "test";
            }

            @Override
            public Environment getEnvironment() {
                return Environment.HOMOLOGATION;
            }

            @Override
            public byte[] signHash(byte[] documentHash, String accessToken) {
                return new byte[0];
            }
        });

        assertThrows(UnsupportedOperationException.class,
                () -> signer.signPdf(new byte[]{0x25, 0x50, 0x44, 0x46}, options));
    }

    @Test
    void builderCreatesOptions() {
        var options = SignatureOptions.builder()
                .withReason("Teste")
                .withLocation("São Paulo - SP")
                .withTimestamp(true)
                .withVisibleSignature(false)
                .build();

        assertNotNull(options);
    }
}
