package org.icpbrasil.signer.core.crypto;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class HashPayloadTest {

    @Test
    void exposesBase64AndHexEncodings() {
        byte[] digest = new byte[32];
        digest[0] = 0x01;
        digest[31] = (byte) 0xFF;

        HashPayload payload = HashPayload.of(digest, DigestAlgorithm.SHA256);

        assertEquals(EncodingUtils.toBase64(digest), payload.toBase64());
        assertEquals(EncodingUtils.toHex(digest), payload.toHex());
    }

    @Test
    void returnsDefensiveCopyOfDigest() {
        byte[] digest = new byte[32];
        HashPayload payload = HashPayload.of(digest, DigestAlgorithm.SHA256);

        digest[0] = 0x7F;
        assertNotEquals(digest[0], payload.getDigest()[0]);
    }
}
