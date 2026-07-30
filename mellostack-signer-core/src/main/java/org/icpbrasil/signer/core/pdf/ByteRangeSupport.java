package org.icpbrasil.signer.core.pdf;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utilitários para parsing e digest do {@code /ByteRange} PAdES.
 */
public final class ByteRangeSupport {

    private static final Pattern BYTE_RANGE_PATTERN = Pattern.compile(
            "/ByteRange\\s*\\[\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\\]"
    );

    private ByteRangeSupport() {
    }

    public static int[] parseByteRange(byte[] pdfBytes) {
        if (pdfBytes == null || pdfBytes.length == 0) {
            throw new IllegalArgumentException("pdfBytes must not be empty");
        }

        Matcher matcher = BYTE_RANGE_PATTERN.matcher(new String(pdfBytes, StandardCharsets.ISO_8859_1));
        if (!matcher.find()) {
            throw new IllegalStateException("/ByteRange not found in prepared PDF");
        }

        return new int[]{
                Integer.parseInt(matcher.group(1)),
                Integer.parseInt(matcher.group(2)),
                Integer.parseInt(matcher.group(3)),
                Integer.parseInt(matcher.group(4))
        };
    }

    public static ContentsSlot resolveContentsSlot(int[] byteRange) {
        validateByteRange(byteRange, Integer.MAX_VALUE);

        int rangeOneStart = byteRange[0];
        int rangeOneLength = byteRange[1];
        int rangeTwoStart = byteRange[2];

        int gapStart = rangeOneStart + rangeOneLength;
        int hexOffset = gapStart + 1;
        int hexLength = rangeTwoStart - hexOffset - 1;

        if (hexLength <= 0) {
            throw new IllegalStateException("Invalid /ByteRange contents slot");
        }

        return new ContentsSlot(hexOffset, hexLength);
    }

    public static byte[] computeDigest(byte[] pdfBytes, int[] byteRange, DigestAlgorithm algorithm) {
        validateByteRange(byteRange, pdfBytes.length);

        MessageDigestHolder digest = new MessageDigestHolder(algorithm);
        digest.update(pdfBytes, byteRange[0], byteRange[1]);
        digest.update(pdfBytes, byteRange[2], byteRange[3]);
        return digest.digest();
    }

    private static void validateByteRange(int[] byteRange, int pdfLength) {
        if (byteRange == null || byteRange.length != 4) {
            throw new IllegalArgumentException("byteRange must contain exactly 4 values");
        }

        int rangeOneStart = byteRange[0];
        int rangeOneLength = byteRange[1];
        int rangeTwoStart = byteRange[2];
        int rangeTwoLength = byteRange[3];

        if (rangeOneStart < 0 || rangeOneLength < 0 || rangeTwoStart < 0 || rangeTwoLength < 0) {
            throw new IllegalArgumentException("byteRange values must be non-negative");
        }

        if (rangeOneStart + rangeOneLength > pdfLength) {
            throw new IllegalArgumentException("first ByteRange segment exceeds PDF length");
        }

        if (rangeTwoStart + rangeTwoLength > pdfLength) {
            throw new IllegalArgumentException("second ByteRange segment exceeds PDF length");
        }

        if (rangeTwoStart <= rangeOneStart + rangeOneLength) {
            throw new IllegalArgumentException("ByteRange segments overlap or are not ordered");
        }
    }

    public record ContentsSlot(int hexOffset, int hexLength) {
    }

    private static final class MessageDigestHolder {

        private final java.security.MessageDigest digest;

        MessageDigestHolder(DigestAlgorithm algorithm) {
            this.digest = algorithm.createMessageDigest();
        }

        void update(byte[] data, int offset, int length) {
            digest.update(data, offset, length);
        }

        byte[] digest() {
            return digest.digest();
        }
    }
}
