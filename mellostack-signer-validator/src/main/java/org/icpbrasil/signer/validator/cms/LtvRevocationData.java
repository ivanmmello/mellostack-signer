package org.icpbrasil.signer.validator.cms;

import java.util.List;
import java.util.Objects;

/**
 * Dados de revogação coletados para embutir no CMS (LTV).
 */
public record LtvRevocationData(List<byte[]> crlResponses, List<byte[]> ocspResponses) {

    public LtvRevocationData {
        crlResponses = List.copyOf(Objects.requireNonNull(crlResponses, "crlResponses"));
        ocspResponses = List.copyOf(Objects.requireNonNull(ocspResponses, "ocspResponses"));
    }

    public static LtvRevocationData empty() {
        return new LtvRevocationData(List.of(), List.of());
    }

    public boolean isEmpty() {
        return crlResponses.isEmpty() && ocspResponses.isEmpty();
    }
}
