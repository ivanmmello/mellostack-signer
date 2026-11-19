package org.icpbrasil.signer.providers.http;

import java.util.Map;

/**
 * Abstração mínima do cliente HTTP para facilitar testes sem expor credenciais.
 */
public interface HttpClientFacade {

    String get(String url, Map<String, String> headers);

    String postJson(String url, Map<String, String> headers, String jsonBody);

    /**
     * POST {@code application/x-www-form-urlencoded}. Implementações que não precisam
     * do fluxo devolvem erro explícito.
     */
    default String postForm(String url, Map<String, String> headers, String formBody) {
        throw new UnsupportedOperationException("postForm is not supported by this HTTP client");
    }
}
