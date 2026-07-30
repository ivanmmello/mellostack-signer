package org.icpbrasil.signer.providers.safeid;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.util.List;

/**
 * Operações SafeID usadas por {@link SafeIdProvider} — abstração para testes.
 */
interface SafeIdGateway {

    List<SafeIdApiClient.SafeIdCertificate> discoverCertificates(String accessToken);

    byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm);
}
