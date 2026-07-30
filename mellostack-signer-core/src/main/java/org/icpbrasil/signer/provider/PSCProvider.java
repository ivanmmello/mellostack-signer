package org.icpbrasil.signer.provider;

import org.icpbrasil.signer.model.Environment;

import java.security.cert.X509Certificate;
import java.util.List;

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
     * <strong>Privacidade:</strong> {@code documentHash} deve ser obtido via
     * {@link org.icpbrasil.signer.core.crypto.DocumentDigestCalculator#createPscPayload}
     * — o PDF original ou preparado nunca deve ser transmitido ao PSC.
     *
     * @param documentHash hash SHA-256 (32 bytes) ou SHA-384 (48 bytes) do ByteRange do PDF
     * @param accessToken  token OAuth2 do usuário final
     * @return assinatura criptográfica raw retornada pelo HSM em nuvem
     */
    byte[] signHash(byte[] documentHash, String accessToken);

    /**
     * Certificado ICP-Brasil do signatário associado ao token OAuth2 (credencial CSC ativa).
     * <p>
     * Drivers devem obter este certificado via API do PSC (ex.: {@code credentials/list} no CSC)
     * antes ou durante {@link #signHash(byte[], String)}.
     */
    X509Certificate getSignerCertificate(String accessToken);

    /**
     * Certificados intermediários da cadeia V12 (exclui o certificado do signatário).
     */
    default List<X509Certificate> getCertificateChain(String accessToken) {
        return List.of();
    }
}
