package org.icpbrasil.signer.providers.serproid;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.util.List;

/**
 * Operações SerproID usadas por {@link SerproIdProvider}.
 */
interface SerproIdGateway {

    List<SerproIdApiClient.SerproIdCertificate> discoverCertificates(String accessToken);

    byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm);

    List<byte[]> signHashes(
            String accessToken,
            String certificateAlias,
            List<byte[]> documentHashes);
}
