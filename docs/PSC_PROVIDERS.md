# Arquitetura de Drivers Plugáveis (PSC)

Este documento descreve como o MelloStack Signer abstrai **Prestadores de Serviço de Confiança (PSCs)** credenciados ICP-Brasil via drivers intercambiáveis.

## Princípio

A aplicação host **não conhece** Bird ID, Remote ID, VIDaaS ou SAFEID diretamente. Ela depende apenas de:

1. Uma instância de `PSCProvider` (driver)
2. A fachada `CloudSigner`

Trocar de PSC = trocar o provider na construção do `CloudSigner`, sem alterar regra de negócio.

```java
CloudSigner signer = new CloudSigner(birdIdProvider);   // Soluti
CloudSigner signer = new CloudSigner(remoteIdProvider); // Certisign
```

## Contrato `PSCProvider`

Localização: `mellostack-signer-core` → `org.icpbrasil.signer.provider.PSCProvider`

```java
public interface PSCProvider {

    String getProviderId();

    Environment getEnvironment();

    byte[] signHash(byte[] documentHash, String accessToken);

    X509Certificate getSignerCertificate(String accessToken);
}
```

| Método | Responsabilidade |
| :--- | :--- |
| `getProviderId()` | Identificador estável do driver (ex.: `birdid`, `remoteid`, `vidaas`, `safeid`) |
| `getEnvironment()` | `HOMOLOGATION` ou `PRODUCTION` — endpoints e credenciais corretos |
| `signHash()` | Envia **apenas o hash** ao PSC com token OAuth2 do usuário; retorna assinatura raw do HSM |
| `signHashes()` | Envia **vários hashes** em uma requisição CSC/ITI (`hashes[]`) — OTP único quando suportado |
| `supportsBatchSigning()` | `true` para drivers ITI (Bird ID, Remote ID, VIDaaS, SafeID) |
| `getSignerCertificate()` | Retorna certificado ICP-Brasil do signatário (credencial CSC ativa) |
| `getCertificateChain()` | Retorna intermediários V12 (opcional; default vazio) |

> **Privacidade:** `signHash()` nunca recebe o PDF completo — somente o digest SHA-256/384 calculado localmente pelo módulo `core`.

## Fluxo de responsabilidades

```text
┌──────────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  Aplicação Host  │     │   CloudSigner (SDK) │     │   PSCProvider    │
│  (ERP, SaaS…)    │     │                     │     │   (driver)       │
└────────┬─────────┘     └──────────┬──────────┘     └────────┬─────────┘
         │                          │                         │
         │ signPdf(pdf, options)    │                         │
         ├─────────────────────────►│                         │
         │                          │ 1. Prepara ByteRange    │
         │                          │ 2. Calcula hash         │
         │                          │                         │
         │                          │ signHash(hash, token)   │
         │                          ├────────────────────────►│
         │                          │                         │ → API PSC
         │                          │◄────────────────────────┤
         │                          │ 3. Monta PKCS#7/PAdES   │
         │◄─────────────────────────┤                         │
         │ PDF assinado             │                         │
```

| Camada | Módulo | O que faz |
| :--- | :--- | :--- |
| Host | — | OAuth2 do usuário, UI, persistência do PDF |
| SDK | `mellostack-signer-sdk` | Orquestra core + provider + validator |
| Core | `mellostack-signer-core` | PDF, ByteRange, hash, CMS — **agnóstico ao PSC** |
| Driver | `mellostack-signer-providers` | HTTP/OAuth2/CSC específico de cada PSC |
| Validator | `mellostack-signer-validator` | ACT, CRL/OCSP, LTV |

## Implementações previstas (Fase 2)

| `getProviderId()` | Classe (prevista) | PSC | Protocolo |
| :--- | :--- | :--- | :--- |
| `birdid` | `BirdIdProvider` | Soluti / Bird ID | OAuth2 + REST CSC |
| `remoteid` | `RemoteIdProvider` | Certisign / Remote ID | OAuth2 + REST ITI (`/v0/oauth/*`) |
| `vidaas` | `VidaasProvider` | Valid / VIDaaS | OAuth2 PKCE + REST ITI (hash Base64) |
| `safeid` | `SafeIdProvider` | Safeweb / SAFEID | OAuth2 + REST |
| `serproid` | `SerproIdProvider` | Serpro / SerproID | OAuth2 PKCE + REST ITI (hash Base64, RAW, SHA-256) |
| `bry` | `BryProvider` | Integra Bry (hub) | JWT da aplicação + HUB Signer CMS por hash |

Cada driver expõe um **Builder** para credenciais de parceiro:

```java
PSCProvider provider = new BirdIdProviderBuilder()
        .withClientId(System.getenv("BIRDID_CLIENT_ID"))
        .withClientSecret(System.getenv("BIRDID_CLIENT_SECRET"))
        .withEnvironment(Environment.HOMOLOGATION)
        .build();

BirdIdProvider birdId = (BirdIdProvider) provider;
OAuth2PkceGenerator.PkceChallenge pkce = birdId.oauth2().generatePkceChallenge();
String authUrl = birdId.oauth2().buildAuthorizationUrl(pkce, redirectUri, state);
// Host redireciona usuário → OTP no app Bird ID → callback com ?code=

PSCProvider remoteIdProvider = new RemoteIdProviderBuilder()
        .withClientId(System.getenv("REMOTEID_CLIENT_ID"))
        .withClientSecret(System.getenv("REMOTEID_CLIENT_SECRET"))
        .withApiBaseUrl(System.getenv("REMOTEID_API_BASE_URL")) // fornecida pela Certisign
        .withEnvironment(Environment.HOMOLOGATION)
        .build();

PSCProvider vidaasProvider = new VidaasProviderBuilder()
        .withClientId(System.getenv("VIDAAS_CLIENT_ID"))
        .withClientSecret(System.getenv("VIDAAS_CLIENT_SECRET"))
        .withEnvironment(Environment.HOMOLOGATION)
        .build();
// VIDaaS: credenciais via POST /v0/oauth/application em hml-certificado.vidaas.com.br

PSCProvider safeIdProvider = new SafeIdProviderBuilder()
        .withClientId(System.getenv("SAFEID_CLIENT_ID"))
        .withClientSecret(System.getenv("SAFEID_CLIENT_SECRET"))
        .withEnvironment(Environment.HOMOLOGATION)
        .build();

PSCProvider serproId = new SerproIdProviderBuilder()
        .withClientId(System.getenv("SERPROID_CLIENT_ID"))
        .withClientSecret(System.getenv("SERPROID_CLIENT_SECRET"))
        .withEnvironment(Environment.HOMOLOGATION)
        .build();
```

> **SerproID:** PSC direto, no mesmo molde de Bird ID e SafeID. OAuth2 Authorization Code + PKCE; a troca do `code` é `application/x-www-form-urlencoded`. A assinatura é RAW (PKCS#1) sobre hash SHA-256 em Base64, e o `CloudSigner` monta o PKCS#7. SHA-384 não é aceito. O lote nativo aceita no máximo 5 hashes. Homologação: `https://hom.serproid.serpro.gov.br/oauth`. Produção: `https://serproid.serpro.gov.br/oauth`. Credenciais e certificado de teste saem do [manual SerproID](https://serproid.serpro.gov.br/manual-integracao/suporte/insumos-homologacao/). Homologação real ainda não foi executada.

```java
BryProvider bry = new BryProviderBuilder()
        .withClientId(System.getenv("BRY_CLIENT_ID"))
        .withClientSecret(System.getenv("BRY_CLIENT_SECRET"))
        .withEnvironment(Environment.HOMOLOGATION)
        .buildProvider();
BryAuthorizationLink link = bry.authorization().createLink(BryAuthorizationRequest.builder()
        .psc(BryPsc.BIRD_ID)
        .redirectUri(redirectUri)
        .state(state)
        .scope(BrySignatureScope.SINGLE_SIGNATURE)
        .numberOfDocuments(1)
        .build());
// Host abre link.authorizationUrl(). No callback só volta state.
// link.signerToken() entra em SignatureOptions.withUserAccessToken().
```

> **Integra Bry:** não é um PSC direto. O JWT (`client_credentials`) autentica a aplicação. O token do signatário sai de `POST /psc/link` e o HUB devolve o CMS pronto (`formatoAssinatura=HASH`). O `CloudSigner` injeta esse CMS sem remontar o PKCS#7. Só SHA-256. PSCs do hub: Syn, SafeID, SerproID, RemoteID, BirdID, Vidaas, DS Cloud.

### Estado da Integra Bry

O fluxo combinado está no SDK, na CLI, nos exemplos e no portal demo: JWT da aplicação, `POST /psc/link`, callback só com `state`, CMS por hash SHA-256 e injeção desse CMS no PDF. No demo, o provider é `bry` e o PSC do hub sai de `PSC_BRY_PSC` (padrão `BirdID`).

Os testes automatizados usam respostas simuladas. Homologação e produção seguem em aberto: nenhuma chamada real foi feita a `integra.hom.bry.com.br` nem ao HUB. O primeiro PDF assinado de verdade ainda pode exigir um ajuste pequeno em dois pontos que a documentação da Bry deixa ambíguos:

1. **`kms_data.url`** vai para a base da Integra do ambiente (`https://integra.hom.bry.com.br/api/service` ou `https://integra.bry.com.br/api/service`). Se o HUB recusar, troque com `BryProviderBuilder.withPscServiceUrl(...)`.
2. **CMS perfil `BASIC`** precisa caber no slot PAdES e passar no verificador do ITI. Se o pacote vier incompleto, o ajuste é no perfil ou na política enviada ao HUB. A fachada `CloudSigner.signPdf` permanece a mesma.

> **Remote ID:** a Certisign não publica URLs fixas como o Bird ID. A `apiBaseUrl` é obrigatória e vem do processo de integração comercial.

## OAuth2 — responsabilidade do host

O SDK **não** implementa UI de login. O fluxo OAuth2 (Authorization Code + PKCE) é responsabilidade da aplicação host ou do [portal demo](../apps/README.md) em homologação.

O host deve:

1. Redirecionar o usuário ao PSC
2. Receber o callback com `code`
3. Trocar `code` por `access_token`
4. Passar o token em `SignatureOptions.withUserAccessToken()`

O driver usa o token apenas na chamada `signHash()` ou `signHashes()` (lote).

### Assinatura em lote (Release 1.1.0)

```java
CloudSigner signer = new CloudSigner(birdIdProvider);

List<byte[]> signedPdfs = signer.signPdfBatch(
        List.of(contratoPdf, anexoPdf, termoPdf),
        SignatureOptions.builder()
                .withUserAccessToken(tokenOAuth2Usuario)
                .withReason("Assinatura em lote")
                .build());
```

- O SDK prepara cada PDF localmente (hash ByteRange) e envia **todos os hashes** em **uma** requisição REST ao PSC.
- Drivers ITI (`birdid`, `remoteid`, `vidaas`, `safeid`) implementam `signHashes()` nativo — **OTP único** para o lote (conforme política do PSC).
- Limite: `BatchSigningLimits.MAX_DOCUMENTS` (50) por requisição.
- Homologação opt-in: `PscHomologationIT#birdIdSignsPdfBatchInHomologation` (mesmas variáveis de ambiente do teste single).

## Tratamento de erros

Drivers devem mapear erros HTTP/API para exceções tipadas (a serem definidas na Fase 2):

| Situação | Comportamento esperado |
| :--- | :--- |
| Token expirado | Exceção com indicativo de re-autenticação |
| OTP inválido | Exceção recuperável (usuário pode tentar novamente) |
| Certificado revogado/expirado | Exceção não recuperável |
| Timeout / 5xx PSC | Retry configurável no cliente HTTP interno |

## Estender com novo PSC

1. Criar classe em `mellostack-signer-providers` implementando `PSCProvider`
2. Implementar cliente HTTP + fluxo OAuth2/CSC conforme documentação oficial do PSC
3. Adicionar testes unitários com respostas mockadas
4. Validar em ambiente de **homologação** do prestador
5. Atualizar tabela de compatibilidade na [documentação técnica](../Documentacao_ICP_Brasil_Cloud_Signer_V12.md)

## Referências

- [Documentação técnica V12](../Documentacao_ICP_Brasil_Cloud_Signer_V12.md)
- [Guia de contribuição](../CONTRIBUTING.md)
- [Cloud Signature Consortium (CSC)](https://cloudsignatureconsortium.org/)
