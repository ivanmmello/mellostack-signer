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

## Reportar vulnerabilidades

Reporte problemas de segurança de forma privada ao mantenedor do repositório — **não** abra issue pública com detalhes exploráveis.
