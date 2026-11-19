# MelloStack Signer CLI

Ferramenta de linha de comando para assinar PDFs com certificado **ICP-Brasil em nuvem** (PAdES V12). O PDF permanece local — apenas o hash do ByteRange é enviado ao PSC.

## Requisitos

- **JVM:** Java 17+ e o JAR fat (`mellostack-signer.jar`), **ou**
- **Nativo:** binário GraalVM (sem JVM instalada)

Credenciais OAuth2 do PSC e access token do usuário (mesmas variáveis dos [exemplos](../examples/README.md)).

## Build

```bash
# JAR executável (fat)
mvn -pl mellostack-signer-cli -am package -DskipTests

# Binário nativo (requer GraalVM 17+ no PATH)
mvn -pl mellostack-signer-cli -am package -DskipTests -Pnative
```

Artefatos:

| Artefato | Caminho |
| :--- | :--- |
| JAR fat | `mellostack-signer-cli/target/mellostack-signer.jar` |
| Binário nativo | `mellostack-signer-cli/target/mellostack-signer` (ou `.exe` no Windows) |

## Uso

### Assinar um PDF

```bash
java -jar mellostack-signer.jar sign contrato.pdf -o contrato-assinado.pdf \
  --client-id "$PSC_CLIENT_ID" \
  --client-secret "$PSC_CLIENT_SECRET" \
  --token "$PSC_USER_ACCESS_TOKEN"
```

Com variáveis de ambiente (flags opcionais):

```bash
export PSC_PROVIDER=birdid
export PSC_CLIENT_ID=...
export PSC_CLIENT_SECRET=...
export PSC_USER_ACCESS_TOKEN=...

java -jar mellostack-signer.jar sign contrato.pdf -o assinado.pdf
```

### Assinar em lote (batch)

Uma autorização PSC / OTP para vários documentos (até 50):

```bash
java -jar mellostack-signer.jar sign-batch doc1.pdf doc2.pdf doc3.pdf \
  -d ./assinados/ \
  --token "$PSC_USER_ACCESS_TOKEN"
```

### Opções PSC

| Flag | Variável de ambiente | Descrição |
| :--- | :--- | :--- |
| `--provider` | `PSC_PROVIDER` | `birdid`, `remoteid`, `vidaas`, `safeid` (padrão: birdid) |
| `--client-id` | `PSC_CLIENT_ID` | OAuth2 client_id |
| `--client-secret` | `PSC_CLIENT_SECRET` | OAuth2 client_secret |
| `--token` | `PSC_USER_ACCESS_TOKEN` | Access token do usuário |
| `--environment` | `PSC_ENVIRONMENT` | `homologation` ou `production` |
| `--certificate-alias` | `PSC_CERTIFICATE_ALIAS` | Alias do certificado (opcional) |
| `--api-base-url` | `PSC_API_BASE_URL` | Obrigatório para Remote ID |
| `--reason` | `SIGN_REASON` | Motivo da assinatura |
| `--location` | `SIGN_LOCATION` | Local da assinatura |
| `--timestamp` | — | PAdES-T com carimbo de tempo |
| `--visible` | — | Assinatura visível no PDF |
| `--validate` | — | Pré-validação local DOC-ICP-15 após assinar |

## Binário nativo

Após `mvn -Pnative package`:

```bash
./mellostack-signer sign contrato.pdf -o assinado.pdf --token "$PSC_USER_ACCESS_TOKEN"
```

Releases oficiais publicam binários para Linux, Windows e macOS no [GitHub Releases](https://github.com/ivanmmello/mellostack-signer/releases).

## Exit codes

| Código | Significado |
| :---: | :--- |
| 0 | Sucesso |
| 1 | Erro de uso ou exceção |
| 2 | Assinatura OK, mas `--validate` falhou na pré-validação |

## Verificação ITI

A pré-validação local (`--validate`) não substitui o [Verificador de Conformidade](https://verificador.iti.gov.br/) do ITI. Use homologação com certificado de teste antes de produção.
