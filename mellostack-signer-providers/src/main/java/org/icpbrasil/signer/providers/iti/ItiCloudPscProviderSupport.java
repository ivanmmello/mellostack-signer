package org.icpbrasil.signer.providers.iti;

import java.util.List;

/**
 * Utilitários compartilhados pelos drivers PSC no padrão ITI (Bird ID, Remote ID, VIDaaS, SafeID).
 */
public final class ItiCloudPscProviderSupport {

    private ItiCloudPscProviderSupport() {
    }

    public static List<byte[]> signHashesViaDelegate(
            ItiCloudPscApiClient delegate,
            String accessToken,
            String certificateAlias,
            List<byte[]> documentHashes) {
        return delegate.signHashes(
                accessToken,
                certificateAlias,
                ItiCloudPscHashRequests.fromDocumentHashes(documentHashes)
        );
    }
}
