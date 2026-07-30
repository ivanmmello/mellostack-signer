package org.icpbrasil.signer.providers.http;

import java.util.Map;

/**
 * Abstração mínima do cliente HTTP para facilitar testes sem expor credenciais.
 */
public interface HttpClientFacade {

    String get(String url, Map<String, String> headers);

    String postJson(String url, Map<String, String> headers, String jsonBody);
}
