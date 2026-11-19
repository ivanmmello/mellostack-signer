package org.icpbrasil.signer.providers.iti;

import org.icpbrasil.signer.providers.csc.HashAlgorithmOid;

import java.util.ArrayList;
import java.util.List;

/**
 * Converte listas de hash raw em entradas da API CSC/ITI para assinatura em lote.
 */
public final class ItiCloudPscHashRequests {

    private ItiCloudPscHashRequests() {
    }

    public static List<ItiCloudPscApiClient.DocumentHashRequest> fromDocumentHashes(List<byte[]> documentHashes) {
        ItiCloudPscValidation.validateDocumentHashes(documentHashes);
        List<ItiCloudPscApiClient.DocumentHashRequest> requests = new ArrayList<>(documentHashes.size());
        for (int index = 0; index < documentHashes.size(); index++) {
            byte[] hash = documentHashes.get(index);
            requests.add(new ItiCloudPscApiClient.DocumentHashRequest(
                    String.valueOf(index + 1),
                    hash,
                    HashAlgorithmOid.fromHashLength(hash.length)
            ));
        }
        return requests;
    }
}
