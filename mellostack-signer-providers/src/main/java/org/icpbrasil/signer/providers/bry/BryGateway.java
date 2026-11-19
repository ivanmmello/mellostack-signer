package org.icpbrasil.signer.providers.bry;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Operações da Integra Bry usadas pelo {@link BryProvider}.
 */
interface BryGateway {

    List<byte[]> signCmsHashes(String signerToken, List<byte[]> documentHashes);

    X509Certificate fetchCertificate(String signerToken);

    BryAuthorizationLink createAuthorizationLink(BryAuthorizationRequest request);
}
