package org.icpbrasil.signer.providers.bry;

/**
 * PSCs publicados pela Integra Bry. O nome da API é o valor de {@code pscName}.
 */
public enum BryPsc {

    SYN("Syn"),
    SAFE_ID("SafeID"),
    SERPRO_ID("SerproID"),
    REMOTE_ID("RemoteID"),
    BIRD_ID("BirdID"),
    VIDAAS("Vidaas"),
    DS_CLOUD("DS Cloud");

    private final String apiName;

    BryPsc(String apiName) {
        this.apiName = apiName;
    }

    public String apiName() {
        return apiName;
    }

    public static BryPsc fromApiName(String apiName) {
        if (apiName == null || apiName.isBlank()) {
            throw new IllegalArgumentException("pscName must not be blank");
        }
        for (BryPsc psc : values()) {
            if (psc.apiName.equalsIgnoreCase(apiName.trim())
                    || psc.name().equalsIgnoreCase(apiName.trim().replace('-', '_').replace(' ', '_'))) {
                return psc;
            }
        }
        throw new IllegalArgumentException("Unknown Integra Bry PSC: " + apiName);
    }
}
