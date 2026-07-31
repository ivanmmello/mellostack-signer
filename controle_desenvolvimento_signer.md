# Controle de Desenvolvimento — ICP-Brasil Cloud Signer SDK

Documento de acompanhamento de progresso do **ICP-Brasil Cloud Signer SDK** — Biblioteca Java open source (JAR) para assinatura digital qualificada em nuvem conforme a Cadeia V12 da ICP-Brasil.

| Informação | Detalhe |
| :--- | :--- |
| **Nome do Projeto** | `icpbrasil-cloud-signer-sdk` |
| **Repositório** | `mellostack-signer` |
| **Linguagem & Runtime** | Java 17+ / Jakarta EE / Spring Boot Compatible |
| **Padrão de Assinatura** | PAdES / CAdES / XAdES — Cadeia V12 ICP-Brasil |
| **Licença** | Apache License 2.0 (Open Source) |

---

## Legenda

| Símbolo | Significado |
| :---: | :--- |
| `[ ]` | Não iniciado |
| `[~]` | Em andamento |
| `[x]` | Concluído |
| `[!]` | Bloqueado / Impedimento |

---

## Fase 0 — Setup e Infraestrutura do Projeto

### 0.1 Estrutura do Monorepo Maven

- [x] Criar projeto Maven multi-módulo (`mellostack-signer` — parent POM)
- [x] Criar módulo `mellostack-signer-core` (manipulação PDF, hash, PKCS#7)
- [x] Criar módulo `mellostack-signer-providers` (adaptadores OAuth2/CSC por PSC)
- [x] Criar módulo `mellostack-signer-validator` (ACT, CRL/OCSP, políticas DOC-ICP)
- [x] Criar módulo `mellostack-signer-sdk` (fachada unificada / artefato publicável)
- [x] Configurar Java 17+, encoding UTF-8 e plugins (compiler, surefire, javadoc, source)
- [x] Configurar dependências base (Apache PDFBox, Bouncy Castle, Jackson, SLF4J)
- [x] Adicionar arquivo `LICENSE` (Apache 2.0)
- [x] Adicionar arquivo `README.md` com visão geral e quick start
- [x] Configurar `.gitignore` para projetos Java/Maven
- [x] Reservar pasta `apps/` para módulos de homologação (demo-api + demo-web — não publicados)

### 0.2 Documentação e Governança Open Source

- [x] Criar documentação técnica inicial (`Documentacao_ICP_Brasil_Cloud_Signer_V12.md`)
- [x] Criar documento de controle de desenvolvimento (`controle_desenvolvimento_signer.md`)
- [x] Criar `CONTRIBUTING.md` (guidelines de contribuição)
- [x] Criar `CODE_OF_CONDUCT.md`
- [x] Criar `CHANGELOG.md` (Keep a Changelog)
- [x] Definir política de versionamento semântico (SemVer) — `docs/VERSIONING.md`
- [x] Documentar arquitetura de drivers plugáveis (interface `PSCProvider`) — `docs/PSC_PROVIDERS.md`
- [x] Interface `PSCProvider` criada em `mellostack-signer-core` (implementações na Fase 2)

### 0.3 Infraestrutura e DevOps

- [x] Criar repositório GitHub (`ivanmmello/mellostack-signer`) — https://github.com/ivanmmello/mellostack-signer
- [x] Configurar branches (`main` + `develop` + `feature/*`) — documentado em `docs/GITHUB_SETUP.md`
- [x] Configurar esteira CI/CD (GitHub Actions: build, testes, análise estática) — `.github/workflows/ci.yml`
- [x] Configurar workflow de release (`.github/workflows/release.yml`) + publicação Maven Central — `docs/MAVEN_CENTRAL.md`, perfil `-Prelease` no pom
- [x] Configurar badges no README (CI, license, Java 17, Maven Central)
- [x] Configurar Dependabot (Maven + GitHub Actions) — `.github/dependabot.yml`
- [x] Template de Pull Request — `.github/pull_request_template.md`

---

## Fase 1 — Módulo Core (PDF, Hash e PKCS#7)

### 1.1 Manipulação de PDF (Apache PDFBox)

- [x] Implementar preparação de contêiner de assinatura vazio (`/ByteRange`)
- [x] Implementar reserva de espaço para assinatura PKCS#7 no PDF
- [x] Implementar cálculo correto do `ByteRange` para PAdES
- [x] Implementar injeção da assinatura final no slot reservado
- [~] Suportar assinatura visível e invisível no layout PDF — invisível OK; visível pendente
- [x] Validar integridade do PDF após injeção da assinatura

### 1.2 Geração de Hash e Criptografia

- [x] Implementar geração de hash SHA-256 sobre o `ByteRange`
- [x] Implementar suporte a SHA-384 (conformidade V12)
- [x] Garantir que o documento original nunca seja transmitido ao PSC (apenas hash)
- [x] Implementar utilitários de codificação Base64/Hex para payloads de API

### 1.3 Montagem do Envelope PKCS#7 / CMS

- [x] Implementar montagem do CMS SignedData com assinatura raw recebida do PSC
- [x] Incluir atributos assinados obrigatórios: `contentType`, `messageDigest`, `signingTime`
- [x] Incluir atributo `signingCertificateV2` (hash do certificado do signatário)
- [x] Incluir cadeia X.509 V12 (intermediários + raiz ICP-Brasil) no pacote CMS
- [x] Implementar suporte a subfiltro `adbe.pkcs7.detached` (PAdES-BES/T)

### 1.4 Modelos e Fachada Pública

- [x] Criar interface `PSCProvider` (contrato para drivers de PSC)
- [x] Criar classe `CloudSigner` (fachada principal de assinatura — skeleton)
- [x] Criar `SignatureOptions` (Builder: token OAuth2, reason, location, timestamp, visible)
- [x] Criar `SignatureResult` (bytes assinados, metadados, certificado do signatário)
- [x] Criar enum `Environment` (HOMOLOGATION / PRODUCTION)
- [x] Expor API com menos de 10 linhas para assinatura completa (Zero Boilerplate)

---

## Fase 2 — Módulo Providers (Adaptadores Multi-PSC)

### 2.1 Infraestrutura Comum de Providers

- [x] Implementar cliente HTTP reutilizável (timeouts, retry, logging) — `SecureHttpClient` (sem retry automático por segurança; redação de segredos)
- [x] Implementar fluxo OAuth2 Authorization Code + PKCE — `OAuth2PkceGenerator`, `OAuth2AuthorizationUrlBuilder`, `OAuth2TokenClient`
- [x] Implementar refresh de token OAuth2 — `OAuth2TokenClient.refreshToken()`
- [~] Implementar interface CSC (*Cloud Signature Consortium*) genérica — OIDs/formatos em `HashAlgorithmOid` / `CscSignatureFormat`; Bird ID usa API REST proprietária compatível
- [x] Implementar tratamento padronizado de erros por PSC (HTTP 4xx/5xx, OTP inválido, certificado expirado) — `PscException` hierarchy
- [x] Implementar cache seguro de tokens (TTL, invalidação) — `SecureTokenCache` (fingerprint SHA-256)

### 2.2 Soluti — Bird ID

- [x] Implementar `BirdIdProviderBuilder` (Client ID, Client Secret, Environment)
- [x] Implementar fluxo de autorização OAuth2 Bird ID — `BirdIdOAuth2Support`
- [x] Implementar envio de hash para assinatura via API REST CSC — `BirdIdApiClient.signHash()` (formato RAW)
- [x] Implementar suporte a OTP do aplicativo Bird ID — via OAuth2 no navegador (documentado em `docs/SECURITY.md`)
- [ ] Validar em ambiente de homologação Soluti

### 2.3 Certisign — Remote ID

- [x] Implementar `RemoteIdProviderBuilder` (Client ID, Client Secret, **apiBaseUrl** obrigatório, Environment)
- [x] Implementar fluxo OAuth2 / REST ITI — `RemoteIdOAuth2Support` + cliente genérico `ItiCloudPscApiClient`
- [x] Implementar envio de hash para assinatura via API REST CSC — `RemoteIdApiClient.signHash()` (formato RAW)
- [ ] Validar em ambiente de homologação Certisign

### 2.4 Valid — VIDaaS

- [x] Implementar `VidaasProviderBuilder` (Client ID, Client Secret, Environment)
- [x] Implementar fluxo OAuth2 / REST Valid — `VidaasOAuth2Support` (QR Code + push) + `VidaasPushAuthenticationClient`
- [x] Implementar envio de hash para assinatura via API REST CSC — `VidaasApiClient.signHash()` (formato RAW, hash Base64)
- [ ] Validar em ambiente de homologação Valid

### 2.5 Safeweb — SAFEID

- [x] Implementar `SafeIdProviderBuilder` (Client ID, Client Secret, Environment)
- [x] Implementar fluxo OAuth2 / REST Safeweb — `SafeIdOAuth2Support`
- [x] Implementar envio de hash para assinatura via API REST CSC — `SafeIdApiClient.signHash()` (formato RAW, hash hex)
- [ ] Validar em ambiente de homologação Safeweb

### 2.6 Tabela de Compatibilidade PSC

| Prestador (PSC) | Nome Comercial | Protocolo API | Driver | Homologação | Produção |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **Soluti** | Bird ID | OAuth2 / REST CSC | `BirdIdProvider` | [~] | [ ] |
| **Certisign** | Remote ID | OAuth2 / REST Custom | `RemoteIdProvider` | [~] | [ ] |
| **Valid** | VIDaaS | OpenID Connect / REST | `VidaasProvider` | [~] | [ ] |
| **Safeweb** | SAFEID | OAuth2 / REST | `SafeIdProvider` | [~] | [ ] |

---

## Fase 3 — Módulo Validator (ACT, Revogação e LTV)

### 3.1 Carimbo do Tempo (ACT)

- [x] Implementar cliente para Autoridade de Carimbo do Tempo credenciada — `Rfc3161TimestampAuthority` + `ActClientConfig`
- [x] Implementar solicitação de timestamp sobre o hash da assinatura — `TimestampAuthority.requestTimestampToken()`
- [x] Injetar selo temporal no pacote CMS (PAdES-T) — `CmsTimestampEnhancer`
- [x] Suportar ACT configurável por tenant/aplicação — `CloudSigner(PSCProvider, TimestampAuthority)`

### 3.2 Validação de Revogação

- [x] Implementar consulta CRL (Certificate Revocation List) — `CrlRevocationChecker`
- [x] Implementar consulta OCSP (Online Certificate Status Protocol) — `OcspRevocationChecker`
- [x] Implementar cache de respostas CRL/OCSP com TTL configurável — `RevocationResponseCache`
- [x] Tratar certificados revogados ou indeterminados — `CertificateRevocationValidator`, `RevocationException`

### 3.3 Conformidade DOC-ICP e LTV

- [x] Implementar validação de políticas DOC-ICP-15 (algoritmos SHA-2, RSA ≥ 2048 bits) — `DocIcp15PolicyValidator`
- [x] Implementar inclusão de dados para validação de longo prazo (LTV) — `CmsLtvEnhancer`, `LtvRevocationDataCollector`
- [x] Implementar verificador local de assinatura PAdES (pré-validação antes de entrega) — `PadesSignatureVerifier`
- [x] Documentar compatibilidade com validadores ITI (Verificador de Conformidade) — `docs/ITI_VALIDATOR_COMPATIBILITY.md`

---

## Fase 4 — Testes, Exemplos e Developer Experience

### 4.1 Testes Automatizados

- [x] Configurar JUnit 5 + Mockito no projeto
- [x] Testes unitários: cálculo de ByteRange e hash SHA-256/384
- [x] Testes unitários: montagem PKCS#7/CMS com atributos V12
- [x] Testes unitários: parsers de resposta OAuth2/CSC (mocks)
- [x] Testes de integração com PDFs de referência (golden files)
- [x] Testes de integração com ambientes de homologação dos PSCs (`PscHomologationIT`, opt-in via env)
- [x] Configurar cobertura mínima no CI (JaCoCo 60%)

### 4.2 Exemplos e Documentação de Uso

- [x] Criar módulo `examples/` com exemplo mínimo de assinatura PAdES
- [x] Exemplo: configuração Bird ID + assinatura de contrato PDF
- [x] Exemplo: assinatura invisível vs. visível
- [x] Exemplo: assinatura com carimbo do tempo (ACT)
- [x] Exemplo: alternância entre PSCs sem alterar regra de negócio
- [x] Documentar dependência Maven e Gradle no README
- [x] Publicar JavaDoc dos pacotes públicos

### 4.3 Release 1.0.0 (MVP)

- [x] Assinatura PAdES funcional com pelo menos 1 PSC (Bird ID) em homologação — `PscHomologationIT` (execução manual)
- [x] Suporte a cadeia V12 e atributos CAdES/PAdES obrigatórios — golden file + `DocIcp15PolicyValidator`
- [x] Publicação no Maven Central (`com.mellostack.signer:mellostack-signer-sdk:1.0.0`) — tag `v1.0.0` + workflow Release
- [x] Tag de release no GitHub com notas de versão — `v1.0.0`

### 4.4 Portal Demo Host — Simulação de Produção (Homologação)

> ⚠️ **Não faz parte do artefato JAR publicado.** Front-end e API demo existem **apenas para testar o SDK** durante o desenvolvimento, simulando o que um sistema em produção (ERP, jurídico, SaaS) fará quando o usuário final clicar em **"Assinar documento"**.

#### 4.4.1 Backend Demo API (`apps/signer-demo-api`)

- [ ] Criar projeto Spring Boot 3 (porta 8096) em `apps/signer-demo-api`
- [ ] Adicionar dependência do `icpbrasil-cloud-signer-sdk` (módulo local via Maven reactor)
- [ ] Endpoint POST `/api/v1/sign/prepare` — recebe PDF + opções, retorna estado da sessão
- [ ] Endpoint GET `/api/v1/oauth/authorize` — inicia redirect OAuth2 + PKCE para o PSC selecionado
- [ ] Endpoint GET `/api/v1/oauth/callback` — recebe callback, troca code por access token
- [ ] Endpoint POST `/api/v1/sign/execute` — invoca `CloudSigner.signPdf()` com token OAuth2
- [ ] Endpoint GET `/api/v1/sign/{sessionId}/download` — retorna PDF assinado
- [ ] Endpoint GET `/health` — health check
- [ ] Configurar credenciais PSC via variáveis de ambiente (`.env`, nunca commitadas)
- [ ] CORS liberado para o front demo (`signer-demo-web`)
- [ ] Dockerfile + entrada no docker-compose do monorepo (opcional)

#### 4.4.2 Frontend Demo Portal (`apps/signer-demo-web`)

- [ ] Criar projeto React 19 + Vite + TypeScript em `apps/signer-demo-web`
- [ ] Tela **Nova assinatura**: upload PDF (drag & drop), seleção de PSC e ambiente
- [ ] Tela **Autorização**: fluxo OAuth2 (redirect + retorno automático ao callback da API)
- [ ] Tela **OTP**: input de código quando exigido pelo PSC (Bird ID, etc.)
- [ ] Tela **Opções**: reason, location, assinatura visível/invisível, carimbo do tempo (ACT)
- [ ] Tela **Processamento**: feedback visual das etapas (hash → PSC → PKCS#7 → PAdES)
- [ ] Tela **Resultado**: download do PDF assinado + metadados (certificado, data, cadeia V12)
- [ ] Tela **Histórico de testes**: listagem local das assinaturas de homologação da sessão
- [ ] Integração com API demo via fetch/axios (base URL configurável)
- [ ] Layout responsivo mínimo para testes em desktop e mobile

#### 4.4.3 Validação Ponta a Ponta

- [ ] Testar fluxo completo com Bird ID em homologação via portal demo
- [ ] Testar alternância de PSC sem alterar código da API (apenas config/seleção)
- [ ] Documentar no README como subir demo local (`demo-api` + `demo-web`)
- [ ] Marcar explicitamente no README que o portal **não é produto** — é referência de integração

---

## Fase 5 — Evoluções Futuras (Roadmap)

### 5.1 Release 1.1.0 — Assinatura em Lote (Batch Signing)

- [ ] Implementar envio de múltiplos hashes em uma única requisição autorizada
- [ ] Suportar OTP único para lote de documentos
- [ ] API `signPdfBatch(List<byte[]>, SignatureOptions)`
- [ ] Testes de integração com batch em homologação

### 5.2 Release 1.2.0 — CLI GraalVM Native Image

- [ ] Criar módulo CLI (`icpbrasil-cloud-signer-cli`)
- [ ] Comando: assinar PDF via linha de terminal
- [ ] Compilar com GraalVM Native Image (binário standalone)
- [ ] Distribuir releases CLI no GitHub Releases

### 5.3 Release 1.3.0 — XAdES para NF-e

- [ ] Implementar assinatura XAdES para XML
- [ ] Suportar schema de Nota Fiscal Eletrônica (NF-e) com certificado em nuvem
- [ ] Exemplo de integração com emissor de NF-e
- [ ] Validar conformidade com requisitos SEFAZ/ICP-Brasil

### 5.4 Expansões Adicionais

- [ ] Suporte a CAdES detached (arquivos não-PDF)
- [ ] Suporte a múltiplas assinaturas no mesmo PDF (co-assinatura)
- [ ] Integração Spring Boot Starter (`icpbrasil-cloud-signer-spring-boot-starter`)
- [ ] Integração Quarkus Extension
- [ ] SDK Kotlin (wrapper idiomatico sobre o JAR Java)

---

## Cronograma Estimado (Roadmap)

| Fase | Período | Marco |
| :--- | :--- | :--- |
| Fase 0 — Setup | Q3 2026 | Monorepo Maven + CI/CD + docs open source |
| Fase 1 — Core | Q3 2026 | PDF, hash, PKCS#7 e fachada `CloudSigner` |
| Fase 2 — Providers | Q3–Q4 2026 | Drivers Bird ID, Remote ID, VIDaaS, SAFEID |
| Fase 3 — Validator | Q4 2026 | ACT, CRL/OCSP, LTV e conformidade DOC-ICP |
| Fase 4 — Testes & Release | Q4 2026 | Release 1.0.0 no Maven Central |
| Fase 4.4 — Portal Demo | Q3–Q4 2026 | Homologação ponta a ponta (paralelo ao MVP) |
| Fase 5.1 — Batch | Q1 2027 | Release 1.1.0 |
| Fase 5.2 — CLI | Q1 2027 | Release 1.2.0 |
| Fase 5.3 — XAdES/NF-e | Q2 2027 | Release 1.3.0 |

**MVP (Fases 0–4): Q3–Q4 2026**  
**Release 1.0.0: Q4 2026**  
**Evoluções (1.1–1.3): Q1–Q2 2027**

---

## Histórico de Atualizações

| Data | Descrição |
| :--- | :--- |
| 2026-07-29 | Documentação técnica inicial criada (`Documentacao_ICP_Brasil_Cloud_Signer_V12.md`) — arquitetura, fluxo de assinatura, exemplos de código e roadmap |
| 2026-07-29 | Documento de controle de desenvolvimento criado com fases 0–5 mapeadas a partir da documentação técnica |
| 2026-07-30 | Adicionada Fase 4.4 — Portal Demo Host (React + Spring Boot) para homologação; simula fluxo de produção quando usuário solicita assinatura; não compõe o JAR publicado |
| 2026-07-30 | Fase 0.1 concluída: monorepo Maven `mellostack-signer` (core, providers, validator, sdk), Java 17, dependências base, LICENSE, README, .gitignore, apps/, classes skeleton, `mvn verify` OK (3 testes) |
| 2026-07-30 | Fase 0.2 concluída: CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md, docs/VERSIONING.md (SemVer), docs/PSC_PROVIDERS.md, Javadoc PSCProvider |
| 2026-07-30 | Fase 0.3 concluída: GitHub Actions (CI + Release), Dependabot, perfil Maven `-Prelease` (GPG + Central Portal), JaCoCo/Enforcer/SpotBugs, badges README, docs/GITHUB_SETUP.md e MAVEN_CENTRAL.md |
| 2026-07-30 | Repositório GitHub criado e push inicial: `ivanmmello/mellostack-signer` (branches `main` + `develop`) |
| 2026-07-30 | Fase 1.1 concluída (parcial): PadesSignaturePreparer, ByteRangeSupport, PadesSignatureInjector, PdfIntegrityValidator — 12 testes unitários no core |
| 2026-07-30 | Fase 1.2 concluída: DocumentDigestCalculator, HashPayload, EncodingUtils — privacidade PSC (somente hash), Base64/Hex — 23 testes no core |
| 2026-07-30 | Fase 1.3 concluída: CmsEnvelopeAssembler, CmsAssemblyRequest, signingCertificateV2 e atributos PAdES — CMS detached injectável no PDF — 27 testes no core |
| 2026-07-30 | Fase 1.4 concluída: CloudSigner.signPdf() orquestra prepare → PSC → CMS → inject; PSCProvider.getSignerCertificate() — 30 testes totais |
| 2026-07-31 | Fase 4.1 concluída: Mockito, golden files PAdES, JaCoCo 60%, docs/TESTING.md |
| 2026-07-31 | Fase 4.2 concluída: módulo `examples/pades-signing`, README Gradle, perfil `-Pdocs` JavaDoc agregado |
| 2026-07-31 | Fase 4.3 concluída: release `1.0.0`, tag `v1.0.0`, publicação Maven Central via CI |

---

## Diretrizes Fundamentais de Design

> Referência permanente para todas as fases de desenvolvimento.

| Diretriz | Descrição |
| :--- | :--- |
| **Privacidade Total** | O documento do cliente **NUNCA** é enviado ao PSC — apenas o hash SHA-256/384 gerado localmente |
| **Zero Boilerplate** | Assinatura completa em menos de 10 linhas de código Java |
| **Multi-PSC Plugável** | Alternar entre Bird ID, Remote ID, VIDaaS e SAFEID sem alterar regra de negócio |
| **Conformidade V12** | Algoritmos SHA-2, RSA ≥ 2048 bits, atributos CAdES/PAdES e cadeia ICP-Brasil V12 |
| **Open Source** | Apache 2.0, contribuições da comunidade, publicação no Maven Central |

---

> **Meta:** Entregar o SDK open source mais simples e completo para assinatura digital qualificada em nuvem no Brasil — abstraindo OAuth2, ByteRange, PKCS#7 e conformidade V12 para que qualquer sistema Java assine em menos de 10 linhas de código.
