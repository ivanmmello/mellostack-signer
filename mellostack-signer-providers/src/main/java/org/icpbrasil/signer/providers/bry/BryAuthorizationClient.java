package org.icpbrasil.signer.providers.bry;

import java.util.Objects;

/**
 * Gera o link de autenticação da Integra Bry para a aplicação host.
 */
public final class BryAuthorizationClient {

    private final BryGateway gateway;

    BryAuthorizationClient(BryGateway gateway) {
        this.gateway = Objects.requireNonNull(gateway, "gateway");
    }

    public BryAuthorizationLink createLink(BryAuthorizationRequest request) {
        return gateway.createAuthorizationLink(request);
    }
}
