package org.icpbrasil.signer.providers.remoteid;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.util.List;

/**
 * Operações Remote ID usadas por {@link RemoteIdProvider} — abstração para testes.
 */
interface RemoteIdGateway {

    List<RemoteIdApiClient.RemoteIdCertificate> discoverCertificates(String accessToken);

    byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm);
}
