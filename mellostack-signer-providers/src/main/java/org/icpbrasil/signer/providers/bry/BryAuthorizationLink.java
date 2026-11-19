package org.icpbrasil.signer.providers.bry;

/**
 * Credencial do signatário e URL para autenticação no PSC, geradas por {@code POST /psc/link}.
 *
 * @param signerToken     credencial usada em {@code X-API-KEY} e em {@code kms_data.token}
 * @param authorizationUrl URL que o host abre no navegador do usuário
 */
public record BryAuthorizationLink(String signerToken, String authorizationUrl) {
}
