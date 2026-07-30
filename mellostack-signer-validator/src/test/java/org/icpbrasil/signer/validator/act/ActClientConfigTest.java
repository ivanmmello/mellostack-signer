package org.icpbrasil.signer.validator.act;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ActClientConfigTest {

    @Test
    void acceptsHttpsUrl() {
        ActClientConfig config = ActClientConfig.of("https://act.example.com/tsa");
        assertEquals("https", config.tsaUrl().getScheme());
    }

    @Test
    void rejectsHttpUrl() {
        assertThrows(IllegalArgumentException.class,
                () -> ActClientConfig.of("http://act.example.com/tsa"));
    }
}
