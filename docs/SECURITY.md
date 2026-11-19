# Segurança — MelloStack Signer

Este documento descreve as medidas de segurança adotadas no SDK e boas práticas para integradores.

## Princípios

| Princípio | Implementação |
| :--- | :--- |
| **Privacidade do documento** | Apenas o hash SHA-256/384 do `ByteRange` é enviado ao PSC — nunca o PDF |
| **TLS obrigatório** | `SecureHttpClient` rejeita URLs não-HTTPS em produção/homologação |
| **Sem redirects automáticos** | `HttpClient.Redirect.NEVER` evita open redirects |
| **Timeouts** | Connect 10s / request 30s (configurável via `HttpClientConfig`) |
| **Redação de segredos** | Tokens e `client_secret` são redigidos em mensagens de erro (`SensitiveRedactor`) |
| **Cache sem token em claro** | `SecureTokenCache` indexa por SHA-256 fingerprint do access token |
| **PKCE (RFC 7636)** | `OAuth2PkceGenerator` usa `SecureRandom` — obrigatório no fluxo Bird ID |
| **Validação de entrada** | Hash (32/48 bytes), alias, tokens — limites de tamanho e caracteres de controle |

## Credenciais

- **Nunca** commitar `client_secret`, tokens OAuth2 ou certificados no repositório
- Obter credenciais de variáveis de ambiente ou cofre (Vault, AWS Secrets Manager, etc.)
- Rotacionar `client_secret` conforme política do PSC parceiro

## OAuth2 / Escopos Bird ID

Para assinatura, o token deve ser obtido com escopo de assinatura:

- `signature_session` — recomendado para ERP/SaaS (várias assinaturas na validade do token)
- **Não** usar `authentication_session` — não permite assinatura

O OTP do aplicativo Bird ID é solicitado **no login OAuth** (navegador) — o SDK não recebe senha/OTP do usuário.

## Homologação vs produção

| Ambiente | Base URL Bird ID |
| :--- | :--- |
| Homologação | `https://apihom.birdid.com.br` |
| Produção | `https://api.birdid.com.br` |

Use `Environment.HOMOLOGATION` até validar conformidade ICP-Brasil com certificados de teste.

## VIDaaS (Valid)

| Ambiente | Base URL |
| :--- | :--- |
| Homologação | `https://hml-certificado.vidaas.com.br` |
| Produção | `https://certificado.vidaas.com.br` |

- Hash enviado em **Base64** (diferente do Bird ID, que usa hex)
- Cadastro de aplicação: `POST /v0/oauth/application` (retorna `client_id` / `client_secret`)
- Fluxo **push**: `redirect_uri=push://` + polling em `/valid/api/v1/trusted-services/authentications` (intervalo mínimo 1 s)

## SafeID (Safeweb)

| Ambiente | Base URL |
| :--- | :--- |
| Homologação | `https://pscsafeweb.safewebpss.com.br/Service/Microservice/OAuth/api` |
| Produção | `https://psc.safeweb.com.br` |

- Hash enviado em **hexadecimal** (como Bird ID)
- Credenciais via plataforma [SafeID Integração](https://pscsafeweb.safewebpss.com.br/Docs/) ou `POST /v0/oauth/application`

## Integra Bry

| Ambiente | JWT da aplicação | Integra | HUB Signer |
| :--- | :--- | :--- | :--- |
| Homologação | `https://cloud-hom.bry.com.br/token-service/jwt` | `https://integra.hom.bry.com.br/api/service` | `https://hub2.hom.bry.com.br/fw/v1` |
| Produção | `https://cloud.bry.com.br/token-service/jwt` | `https://integra.bry.com.br/api/service` | `https://hub2.bry.com.br/fw/v1` |

- Dois tokens: JWT da aplicação (`client_credentials`) e credencial do signatário (`POST /psc/link`)
- Assinatura CMS com `formatoAssinatura=HASH` e `kms_type=PSC` — o PDF não sai do host
- O callback devolve apenas `state`; o token do signatário já veio na criação do link
- Algoritmo aceito pelo HUB nesse fluxo: SHA-256

O driver está implementado (SDK, CLI, exemplos e portal demo). Homologação com a conta Bry ainda não foi executada. Dois pontos ficam para o primeiro PDF real:

1. `kms_data.url` usa a base da Integra do ambiente. Se o HUB recusar, use `withPscServiceUrl`.
2. O CMS no perfil `BASIC` precisa ser aceito como PAdES no verificador do ITI. Se o pacote vier incompleto, ajuste o perfil ou a política enviada ao HUB.

## SerproID

| Ambiente | Base |
| :--- | :--- |
| Homologação | `https://hom.serproid.serpro.gov.br/oauth` |
| Produção | `https://serproid.serpro.gov.br/oauth` |

- OAuth2 Authorization Code + PKCE; troca do `code` em `application/x-www-form-urlencoded`
- Hash SHA-256 em Base64; resposta RAW. O PKCS#7 é montado localmente
- SHA-384 não é aceito. Lote nativo: no máximo 5 hashes
- Credenciais e certificado de homologação: [manual SerproID](https://serproid.serpro.gov.br/manual-integracao/suporte/insumos-homologacao/)
- Homologação real ainda não foi executada

O driver está no SDK, na CLI, nos exemplos e no portal demo (`serproid`).

## Reportar vulnerabilidades

Reporte problemas de segurança de forma privada ao mantenedor do repositório — **não** abra issue pública com detalhes exploráveis.
