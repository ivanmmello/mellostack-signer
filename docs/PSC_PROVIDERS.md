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
}
```

| Método | Responsabilidade |
| :--- | :--- |
| `getProviderId()` | Identificador estável do driver (ex.: `birdid`, `remoteid`, `vidaas`, `safeid`) |
| `getEnvironment()` | `HOMOLOGATION` ou `PRODUCTION` — endpoints e credenciais corretos |
| `signHash()` | Envia **apenas o hash** ao PSC com token OAuth2 do usuário; retorna assinatura raw do HSM |

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
| `remoteid` | `RemoteIdProvider` | Certisign / Remote ID | OAuth2 + REST custom |
| `vidaas` | `VidaasProvider` | Valid / VIDaaS | OpenID Connect + REST |
| `safeid` | `SafeIdProvider` | Safeweb / SAFEID | OAuth2 + REST |

Cada driver expõe um **Builder** para credenciais de parceiro:

```java
PSCProvider provider = new BirdIdProviderBuilder()
        .withClientId("SEU_CLIENT_ID")
        .withClientSecret("SEU_CLIENT_SECRET")
        .withEnvironment(Environment.HOMOLOGATION)
        .build();
```

## OAuth2 — responsabilidade do host

O SDK **não** implementa UI de login. O fluxo OAuth2 (Authorization Code + PKCE) é responsabilidade da aplicação host ou do [portal demo](../apps/README.md) em homologação.

O host deve:

1. Redirecionar o usuário ao PSC
2. Receber o callback com `code`
3. Trocar `code` por `access_token`
4. Passar o token em `SignatureOptions.withUserAccessToken()`

O driver usa o token apenas na chamada `signHash()`.

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
