package org.icpbrasil.signer.core.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncodingUtilsTest {

    @Test
    void base64RoundTrip() {
        byte[] original = {0x01, 0x02, (byte) 0xFE, 0x7F};
        String encoded = EncodingUtils.toBase64(original);
        assertArrayEquals(original, EncodingUtils.fromBase64(encoded));
    }

    @Test
    void hexRoundTrip() {
        byte[] original = {0x0A, 0x1B, 0x2C};
        assertEquals("0A1B2C", EncodingUtils.toHex(original));
        assertArrayEquals(original, EncodingUtils.fromHex("0a1b2c"));
    }

    @Test
    void rejectsInvalidBase64() {
        assertThrows(IllegalArgumentException.class, () -> EncodingUtils.fromBase64("***"));
    }

    @Test
    void rejectsOddHexLength() {
        assertThrows(IllegalArgumentException.class, () -> EncodingUtils.fromHex("ABC"));
    }
}
