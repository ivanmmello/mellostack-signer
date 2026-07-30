package org.icpbrasil.signer.providers.oauth;

/**
 * Escopos OAuth2 Bird ID / ICP-Brasil.
 *
 * @see <a href="https://docs.vaultid.com.br/workspace/cloud/api/autenticacao-de-usuarios">Bird ID OAuth scopes</a>
 */
public enum OAuth2Scope {

    /** Uma assinatura por token — invalidado após uso. */
    SINGLE_SIGNATURE("single_signature"),

    /** Múltiplas assinaturas em uma requisição — invalidado após uso. */
    MULTI_SIGNATURE("multi_signature"),

    /** Sessão de assinatura — várias chamadas enquanto válido (recomendado para ERP/SaaS). */
    SIGNATURE_SESSION("signature_session"),

    /** Apenas autenticação — não permite assinatura. */
    AUTHENTICATION_SESSION("authentication_session");

    private final String value;

    OAuth2Scope(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
