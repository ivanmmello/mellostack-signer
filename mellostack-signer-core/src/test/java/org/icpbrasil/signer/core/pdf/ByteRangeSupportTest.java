package org.icpbrasil.signer.core.pdf;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ByteRangeSupportTest {

    @Test
    void parsesByteRangeFromPreparedPdfPattern() {
        byte[] pdf = "%PDF-1.4 /ByteRange [0 10 20 5] trailer".getBytes(StandardCharsets.US_ASCII);
        int[] byteRange = ByteRangeSupport.parseByteRange(pdf);

        assertArrayEquals(new int[] {0, 10, 20, 5}, byteRange);
    }

    @Test
    void computesSha384DigestOverTwoRanges() {
        byte[] pdf = "AAAA<0000>BBBB".getBytes(StandardCharsets.US_ASCII);
        int[] byteRange = {0, 4, 10, 4};

        byte[] digest = ByteRangeSupport.computeDigest(pdf, byteRange, DigestAlgorithm.SHA384);

        assertNotNull(digest);
        assertEquals(48, digest.length);
    }

    @Test
    void computesDigestOverTwoRanges() {
        byte[] pdf = "AAAA<0000>BBBB".getBytes(StandardCharsets.US_ASCII);
        int[] byteRange = {0, 4, 10, 4};

        byte[] digest = ByteRangeSupport.computeDigest(pdf, byteRange, DigestAlgorithm.SHA256);

        assertNotNull(digest);
        assertEquals(32, digest.length);
    }

    @Test
    void resolvesContentsSlotFromByteRange() {
        int[] byteRange = {0, 100, 200, 50};
        ByteRangeSupport.ContentsSlot slot = ByteRangeSupport.resolveContentsSlot(byteRange);

        assertEquals(101, slot.hexOffset());
        assertEquals(98, slot.hexLength());
    }

    @Test
    void rejectsInvalidByteRange() {
        byte[] pdf = new byte[] {1, 2, 3};
        assertThrows(IllegalArgumentException.class,
                () -> ByteRangeSupport.computeDigest(pdf, new int[] {0, 10, 20, 5}, DigestAlgorithm.SHA256));
    }
}
