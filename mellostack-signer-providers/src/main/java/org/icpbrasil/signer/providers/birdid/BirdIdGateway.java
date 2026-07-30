package org.icpbrasil.signer.providers.birdid;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.util.List;

/**
 * Operações Bird ID usadas por {@link BirdIdProvider} — abstração para testes.
 */
interface BirdIdGateway {

    List<BirdIdApiClient.BirdIdCertificate> discoverCertificates(String accessToken);

    byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm);
}
