package org.icpbrasil.signer.provider;

import org.icpbrasil.signer.model.Environment;

/**
 * Contrato para drivers plugáveis de Prestadores de Serviço de Confiança (PSC).
 * <p>
 * Implementações ficam em {@code mellostack-signer-providers} (Bird ID, Remote ID,
 * VIDaaS, SAFEID). A aplicação host instancia um driver e passa para {@code CloudSigner}
 * sem alterar regra de negócio ao trocar de PSC.
 * <p>
 * Arquitetura completa: {@code docs/PSC_PROVIDERS.md}
 *
 * @see org.icpbrasil.signer.core.CloudSigner
 */
public interface PSCProvider {

    /**
     * Identificador estável do driver (ex.: {@code birdid}, {@code remoteid}).
     */
    String getProviderId();

    /**
     * Ambiente de operação — homologação ou produção do PSC.
     */
    Environment getEnvironment();

    /**
     * Envia o hash do documento ao PSC para assinatura remota.
     * <p>
     * O PDF original nunca transita por este método — apenas o digest calculado
     * localmente sobre o {@code ByteRange} preparado pelo módulo core.
     *
     * @param documentHash hash SHA-256 ou SHA-384 do ByteRange do PDF
     * @param accessToken  token OAuth2 do usuário final (obtido pelo host)
     * @return assinatura criptográfica raw retornada pelo HSM em nuvem
     */
    byte[] signHash(byte[] documentHash, String accessToken);
}
