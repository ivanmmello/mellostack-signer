# Testes — MelloStack Signer

Guia de execução dos testes automatizados (Fase 4.1).

## Pré-requisitos

- Java 17+
- Maven 3.9+

## Testes unitários (padrão)

Executa todos os testes **exceto** os marcados com `@Tag("integration")`:

```bash
mvn verify -Dspotbugs.skip=true
```

Com perfil CI (Enforcer + JaCoCo + cobertura mínima de 60% por módulo):

```bash
mvn -Pci clean verify -Dspotbugs.skip=true
```

## Testes de integração

Inclui golden files PAdES e (opcionalmente) homologação PSC:

```bash
mvn verify -Dspotbugs.skip=true -Dgroups=integration
```

### Golden file PAdES

- Entrada: `mellostack-signer-sdk/src/test/resources/golden/sample-contract.pdf`
- Hash de referência: `sample-contract.document-hash.hex`
- Teste: `PadesSigningGoldenFileIT` — prepare → sign → `SignatureValidator.validateSignedPdf()`

Para regenerar o hash após alterar o PDF golden, execute manualmente `GoldenHashGenerator` (teste `@Disabled`).

### Homologação PSC (gate de release — Bird ID)

Teste E2E com credenciais reais de homologação Bird ID:

```bash
set PSC_HOMOLOGATION_ENABLED=true
set BIRDID_CLIENT_ID=...
set BIRDID_CLIENT_SECRET=...
set PSC_ACCESS_TOKEN=...
set BIRDID_CERTIFICATE_ALIAS=...   # opcional

mvn -pl mellostack-signer-sdk test -Dgroups=integration -Dtest=PscHomologationIT#birdIdSignsPdfInHomologation
```

Valida: `CloudSigner.signPdf()` → PSC Bird ID → `SignatureValidator` (DOC-ICP-15).

## Stack de testes

| Ferramenta | Uso |
| :--- | :--- |
| **JUnit 5** | Framework de testes |
| **Mockito** | Mocks de `HttpClientFacade`, OAuth2/CSC |
| **JaCoCo** | Cobertura mínima 60% (perfil `-Pci`) |
| **FakeHttpClient** | Stubs HTTP nos testes de API (Bird ID, ITI, etc.) |

## Módulos cobertos

| Módulo | Foco |
| :--- | :--- |
| `mellostack-signer-core` | ByteRange, hash SHA-256/384, CMS/PKCS#7 |
| `mellostack-signer-providers` | OAuth2, parsers CSC/ITI, drivers PSC |
| `mellostack-signer-validator` | ACT, CRL/OCSP, DOC-ICP-15, verificador PAdES |
| `mellostack-signer-sdk` | `CloudSigner` E2E, golden files |
