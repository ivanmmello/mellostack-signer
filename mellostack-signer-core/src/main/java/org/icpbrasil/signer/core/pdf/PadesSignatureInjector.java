package org.icpbrasil.signer.core.pdf;

import org.icpbrasil.signer.core.crypto.EncodingUtils;

import java.util.Locale;

/**
 * Injeta a assinatura PKCS#7/CMS (hex) no slot reservado do PDF preparado.
 */
public final class PadesSignatureInjector {

    public byte[] inject(PreparedSignature prepared, byte[] cmsSignature) {
        if (prepared == null) {
            throw new IllegalArgumentException("prepared must not be null");
        }
        if (cmsSignature == null || cmsSignature.length == 0) {
            throw new IllegalArgumentException("cmsSignature must not be empty");
        }

        return inject(
                prepared.getPreparedPdf(),
                prepared.getContentsHexOffset(),
                prepared.getContentsHexLength(),
                cmsSignature
        );
    }

    public byte[] inject(byte[] preparedPdf, int contentsHexOffset, int contentsHexLength, byte[] cmsSignature) {
        if (preparedPdf == null || preparedPdf.length == 0) {
            throw new IllegalArgumentException("preparedPdf must not be empty");
        }
        if (cmsSignature == null || cmsSignature.length == 0) {
            throw new IllegalArgumentException("cmsSignature must not be empty");
        }
        if (contentsHexOffset < 0 || contentsHexLength <= 0) {
            throw new IllegalArgumentException("invalid contents slot");
        }

        String hexSignature = EncodingUtils.toHex(cmsSignature);
        if (hexSignature.length() > contentsHexLength) {
            throw new IllegalArgumentException(
                    "CMS signature hex length (" + hexSignature.length()
                            + ") exceeds reserved slot (" + contentsHexLength + ")"
            );
        }

        String paddedHex = String.format(Locale.ROOT, "%-" + contentsHexLength + "s", hexSignature)
                .replace(' ', '0');

        byte[] signedPdf = preparedPdf.clone();
        byte[] hexBytes = paddedHex.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(hexBytes, 0, signedPdf, contentsHexOffset, hexBytes.length);
        return signedPdf;
    }
}
