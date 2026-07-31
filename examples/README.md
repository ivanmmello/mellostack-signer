# Exemplos — MelloStack Signer

Módulo **`examples/pades-signing`** com programas Java executáveis que demonstram integração real com PSC em homologação.

> **Privacidade:** o PDF permanece na máquina local. Apenas o hash SHA-256/384 do ByteRange é enviado ao PSC.

## Pré-requisitos

- Java 17+
- Maven 3.9+
- Credenciais OAuth2 do PSC (client id/secret) e **token de acesso do usuário** (`PSC_USER_ACCESS_TOKEN`)
- Ambiente de homologação do PSC contratado

## Build

```bash
mvn -pl examples/pades-signing -am package -DskipTests
```

## Variáveis de ambiente comuns

| Variável | Obrigatória | Descrição |
| :--- | :---: | :--- |
| `PSC_CLIENT_ID` | Sim | Client ID OAuth2 do integrador |
| `PSC_CLIENT_SECRET` | Sim | Client secret OAuth2 |
| `PSC_USER_ACCESS_TOKEN` | Sim | Access token do usuário após autorização OAuth2 |
| `PSC_PROVIDER` | Não | `birdid` (padrão), `remoteid`, `vidaas`, `safeid` |
| `PSC_ENVIRONMENT` | Não | `homologation` (padrão) ou `production` |
| `PSC_CERTIFICATE_ALIAS` | Não | Alias quando o usuário possui múltiplos certificados |
| `PSC_API_BASE_URL` | Remote ID | URL base fornecida pela Certisign |
| `ACT_TSA_URL` | PAdES-T | URL HTTPS da ACT (RFC 3161) |
| `INPUT_PDF` | Não | Caminho para PDF de entrada (padrão: `sample-contract.pdf` no classpath) |
| `OUTPUT_PDF` | Não | Caminho do PDF assinado de saída |

## Exemplos

### 1. Assinatura mínima PAdES

```bash
export PSC_CLIENT_ID=...
export PSC_CLIENT_SECRET=...
export PSC_USER_ACCESS_TOKEN=...

mvn -pl examples/pades-signing exec:java \
  -Dexec.mainClass=org.icpbrasil.signer.examples.MinimalPadesSigningExample
```

### 2. Bird ID + contrato PDF

```bash
export PSC_ENVIRONMENT=homologation
mvn -pl examples/pades-signing exec:java \
  -Dexec.mainClass=org.icpbrasil.signer.examples.BirdIdContractSigningExample
```

### 3. Assinatura visível vs. invisível

Gera `signed-invisible.pdf` e `signed-visible.pdf`:

```bash
mvn -pl examples/pades-signing exec:java \
  -Dexec.mainClass=org.icpbrasil.signer.examples.VisibleInvisibleSignatureExample
```

### 4. Carimbo do tempo (PAdES-T)

```bash
export ACT_TSA_URL=https://act-homolog.example/tsa
mvn -pl examples/pades-signing exec:java \
  -Dexec.mainClass=org.icpbrasil.signer.examples.TimestampSigningExample
```

### 5. Alternância entre PSCs

Mesmo código — altere apenas `PSC_PROVIDER`:

```bash
export PSC_PROVIDER=birdid   # ou remoteid, vidaas, safeid
mvn -pl examples/pades-signing exec:java \
  -Dexec.mainClass=org.icpbrasil.signer.examples.MultiPscSigningExample
```

## OAuth2 do usuário

Os exemplos assumem que a aplicação host já concluiu o fluxo OAuth2 (authorization code + PKCE) e possui o `PSC_USER_ACCESS_TOKEN`. Para Bird ID, use `BirdIdOAuth2Support` no módulo `mellostack-signer-providers` — veja [docs/PSC_PROVIDERS.md](../docs/PSC_PROVIDERS.md).

## Windows (PowerShell)

```powershell
$env:PSC_CLIENT_ID = "..."
$env:PSC_CLIENT_SECRET = "..."
$env:PSC_USER_ACCESS_TOKEN = "..."
mvn -pl examples/pades-signing exec:java `
  -Dexec.mainClass=org.icpbrasil.signer.examples.MinimalPadesSigningExample
```
