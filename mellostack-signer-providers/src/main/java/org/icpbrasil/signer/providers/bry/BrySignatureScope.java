package org.icpbrasil.signer.providers.bry;

/**
 * Escopos de autorização da Integra Bry ({@code /psc/link}).
 */
public enum BrySignatureScope {

    SINGLE_SIGNATURE("single_signature"),
    MULTI_SIGNATURE("multi_signature"),
    SIGNATURE_SESSION("signature_session");

    private final String apiValue;

    BrySignatureScope(String apiValue) {
        this.apiValue = apiValue;
    }

    public String apiValue() {
        return apiValue;
    }
}
