package org.icpbrasil.signer.providers.vidaas;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;

import java.util.List;

/**
 * Operações VIDaaS usadas por {@link VidaasProvider} — abstração para testes.
 */
interface VidaasGateway {

    List<VidaasApiClient.VidaasCertificate> discoverCertificates(String accessToken);

    byte[] signHash(
            String accessToken,
            String certificateAlias,
            byte[] documentHash,
            DigestAlgorithm digestAlgorithm);
}
