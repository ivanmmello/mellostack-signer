package com.mellostack.signer.demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "demo")
public class DemoProperties {

    private String frontendUrl = "http://localhost:5173";
    private String oauthRedirectUri = "http://localhost:8096/api/v1/oauth/callback";
    private final Psc psc = new Psc();
    private final Act act = new Act();

    public String frontendUrl() {
        return frontendUrl;
    }

    public void setFrontendUrl(String frontendUrl) {
        this.frontendUrl = frontendUrl;
    }

    public String oauthRedirectUri() {
        return oauthRedirectUri;
    }

    public void setOauthRedirectUri(String oauthRedirectUri) {
        this.oauthRedirectUri = oauthRedirectUri;
    }

    public Psc psc() {
        return psc;
    }

    public Act act() {
        return act;
    }

    public static final class Psc {
        private String provider = "birdid";
        private String environment = "homologation";
        private String clientId = "";
        private String clientSecret = "";
        private String apiBaseUrl = "";
        private String certificateAlias = "";

        public String provider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String environment() {
            return environment;
        }

        public void setEnvironment(String environment) {
            this.environment = environment;
        }

        public String clientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String clientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String apiBaseUrl() {
            return apiBaseUrl;
        }

        public void setApiBaseUrl(String apiBaseUrl) {
            this.apiBaseUrl = apiBaseUrl;
        }

        public String certificateAlias() {
            return certificateAlias;
        }

        public void setCertificateAlias(String certificateAlias) {
            this.certificateAlias = certificateAlias;
        }
    }

    public static final class Act {
        private String tsaUrl = "";

        public String tsaUrl() {
            return tsaUrl;
        }

        public void setTsaUrl(String tsaUrl) {
            this.tsaUrl = tsaUrl;
        }
    }
}
