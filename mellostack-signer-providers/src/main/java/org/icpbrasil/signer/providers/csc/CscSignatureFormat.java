package org.icpbrasil.signer.providers.csc;

/**
 * Formatos de assinatura suportados por APIs CSC / Bird ID.
 */
public enum CscSignatureFormat {

    /** PKCS#1 v1.5 raw — usado pelo MelloStack Signer para montagem local do CMS. */
    RAW("RAW"),

    /** CMS detached gerado pelo PSC (não utilizado pelo SDK neste momento). */
    CMS("CMS");

    private final String apiValue;

    CscSignatureFormat(String apiValue) {
        this.apiValue = apiValue;
    }

    public String apiValue() {
        return apiValue;
    }
}
