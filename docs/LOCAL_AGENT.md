# MelloStack Signer Agent — Certificados locais (A1/A3)

Documento de arquitetura e requisitos para o **agente desktop genérico** que complementa o SDK de nuvem. Destinado a **qualquer integrador** (ERP, jurídico, SaaS, órgão público) — não a um sistema específico.

## Visão do produto

| Componente | Público | Install no PC do usuário |
| :--- | :--- | :---: |
| **MelloStack Signer SDK** (Maven) | Desenvolvedor backend | Não |
| **Modo nuvem** (`CloudSigner` + PSC) | Signatário com e-CPF/e-CNPJ em nuvem | Não (apenas app do PSC no celular) |
| **MelloStack Signer Agent** | Signatário com token USB / cartão / A1 | **Sim** — instalador leve único |

O agente expõe API REST em `127.0.0.1` (porta configurável, padrão proposto `9180`). Aplicações web carregam `mellostack-agent.js` (equivalente genérico ao padrão *browser → localhost*) e assinam **PAdES ICP-Brasil V12**, reutilizando o mesmo core PDF/CMS do SDK.

Referências de mercado (apenas padrão arquitetural, **sem dependência**):

- Agente local + REST loopback + consentimento do usuário
- **Não** reutiliza CriptoCNS/xapiripe nem APIs proprietárias

---

## Problema conhecido: incompatibilidade entre middlewares (SafeNet, dxSafe, etc.)

### O que ocorre em soluções legadas

Alguns agentes Windows enumeram certificados via **CryptoAPI/CNG global** ou assumem **um único** Cryptographic Service Provider (CSP) / Key Storage Provider (KSP) por máquina.

Quando o usuário possui **mais de um middleware** instalado — por exemplo **SafeNet** (Gemalto/Thales) **e** **dxSafe** (Valid/Serpro) — podem ocorrer:

| Sintoma | Causa típica |
| :--- | :--- |
| Agente não inicia ou trava ao enumerar certs | Conflito de DLLs PKCS#11 / CSP |
| Certificado errado selecionado | Ordem de enumeração global imprevisível |
| Assinatura falha intermitente | `CryptAcquireCertificatePrivateKey` aponta para provider incorreto |
| Funciona em uma máquina e falha em outra | Combinação única de drivers instalados |

**Requisito MelloStack:** o Signer Agent **deve operar com SafeNet + dxSafe + Windows Store + outros PKCS#11 simultaneamente**, sem exigir desinstalação de middleware concorrente.

### Estratégia de compatibilidade (obrigatória)

#### 1. Nunca depender de enumeração CryptoAPI global como caminho único

- Cada backend de certificado é um **`CertificateBackend` independente**
- Backends previstos: `pkcs11`, `windows-store` (opcional), `pkcs12-file` (A1)

#### 2. PKCS#11 explícito por módulo (não “primeiro CSP do sistema”)

Cada biblioteca nativa é registrada **isoladamente**:

```text
%ProgramData%/MelloStack/signer-agent/pkcs11/
  safenet.conf      → library = C:\Windows\System32\dkck201.dll
  dxsafe.conf       → library = C:\Program Files\...\dxpkcs11.dll
  custom-ac.conf    → (integrador corporativo via GPO)
```

O agente carrega **config SunPKCS11 separada por vendor**, nunca um pool monolítico que merge drivers incompatíveis.

#### 3. Isolamento de processo para DLLs conflitantes (Worker Pool)

Quando dois módulos PKCS#11 não coexistem na mesma JVM (casos documentados em campo):

```text
Agent (orquestrador REST, Java)
  ├── Worker safenet.exe  → JVM filha + safenet.conf apenas
  ├── Worker dxsafe.exe   → JVM filha + dxsafe.conf apenas
  └── Agregador unifica lista de certificados com metadado sourceModule
```

- Falha em um worker **não derruba** os demais
- PIN e assinatura ocorrem **no worker do módulo correto**
- Comunicação inter-processo: gRPC localhost ou stdin/stdout JSON (sem rede externa)

#### 4. Lista unificada com identidade estável

Cada certificado exposto na API:

```json
{
  "id": "pkcs11:safenet:slot0:abc123",
  "sourceModule": "safenet",
  "slotLabel": "SafeNet Token",
  "subjectCn": "JOAO DA SILVA:12345678900",
  "issuerCn": "AC VALID RFB v5",
  "serialNumber": "...",
  "notAfter": "2027-07-12T..."
}
```

A assinatura referencia `certificateId` — **nunca** índice frágil de enumeração global.

#### 5. Detecção e degradação graciosa

| Situação | Comportamento |
| :--- | :--- |
| Módulo A falha ao carregar | Log + módulo B/C continuam; UI lista apenas backends saudáveis |
| Token removido mid-sign | Erro tipado `TOKEN_UNAVAILABLE`; não corrompe outros módulos |
| PIN incorreto | Erro recuperável; sem retry automático do PIN |

#### 6. Testes de compatibilidade (CI manual)

Matriz mínima de homologação documentada:

- SafeNet apenas
- dxSafe apenas
- SafeNet **+** dxSafe instalados
- Windows software KSP + token USB
- A1 PKCS#12 (sem token)

---

## Stack tecnológica recomendada

### Núcleo do agente: **Java 17 LTS + JPackage**

| Critério | Java 17 + JPackage |
| :--- | :--- |
| Reuso do SDK | **100%** — `LocalSigner`, core PAdES, validator, ACT/LTV |
| PKCS#11 | `SunPKCS11` — múltiplos `.conf` por vendor |
| Cross-platform | Windows (prioridade), Linux, macOS |
| Instalador | MSI/EXE via `jpackage` — um artefato por release |
| Segurança memória | JVM isolada; PIN em `char[]` zerado após uso; sem log de segredos |
| Manutenção | Mesmo repositório Maven, mesma equipe |

**Por que não Electron/Node (como xapiripe):** repetiría dependência de CryptoAPI Windows e duplicaria lógica PAdES fora do SDK.

**Por que não Rust/Go como núcleo completo:** exigiria reimplementar PAdES V12 ou acoplar JVM de qualquer forma — complexidade sem ganho no core.

### Componente opcional: **Rust** (somente worker PKCS#11)

Use **Rust** apenas se testes de campo provarem DLL conflict intra-JVM:

- Crate `cryptoki` / `pkcs11` + binário `mellostack-pkcs11-worker` (~2 MB)
- Agente Java spawn worker por módulo
- Interface estável protobuf/JSON — substituível sem mudar API REST pública

### UI bandeja (tray)

- **Fase 1:** JavaFX ou AWT SystemTray (zero Electron)
- **Fase 2 (opcional):** Tauri (Rust shell + WebView leve) **apenas** para UI; crypto permanece no JVM

---

## Segurança (realista e robusta)

### O que implementamos agora (ICP-Brasil V12 vigente)

| Controle | Implementação |
| :--- | :--- |
| Loopback only | `127.0.0.1` — sem exposição LAN/WAN |
| CORS / origens | Allowlist por integrador (`allowedOrigins`) |
| Consentimento | Dialog nativo antes de cada assinatura (configurável TTL sessão) |
| PIN | Solicitado no agente; nunca trafega para o browser em claro |
| TLS | N/A no loopback; comunicação browser↔agent via host local |
| Segredos | PIN e PFX em memória efêmera; redaction em logs (`SensitiveRedactor`) |
| PDF | Processado localmente; hash assinado no token — PDF não sai da máquina |
| Atualização | Assinatura de release (code signing MSI); auto-update opcional |

### Criptografia pós-quântica (expectativa honesta)

A **ICP-Brasil V12 atual** exige **RSA 2048+** e **SHA-256** (DOC-ICP-15). Certificados em token e PSC **não** usam algoritmos pós-quânticos (ML-DSA, ML-KEM) na cadeia vigente em 2026.

O agente adota **agilidade criptográfica** (*crypto agility*):

- Abstração `SignatureAlgorithm` no core — troca de algoritmo quando ITI/ICP publicar PQC
- TLS 1.3 para comunicações externas (update, OCSP, ACT)
- Documentação **não** promete “assinatura quântica” hoje — promete conformidade V12 + roadmap PQC quando normatizado

Quando o ITI credenciar PQC, o MelloStack atualiza core + agent na mesma release — sem redesign do agente.

---

## API REST proposta (genérica)

Base: `http://127.0.0.1:9180`

| Método | Path | Descrição |
| :--- | :--- | :--- |
| GET | `/health` | Agente online + versão |
| GET | `/v1/backends` | Módulos PKCS#11 carregados e status |
| GET | `/v1/certificates` | Lista unificada (todos backends saudáveis) |
| POST | `/v1/sign/pdf` | Entrada: PDF + `certificateId` + PIN → PDF PAdES V12 |
| POST | `/v1/sign/hash` | Entrada: hash + `certificateId` → assinatura raw (avançado) |

OpenAPI publicada em `docs/openapi/signer-agent.yaml` (a criar na implementação).

### SDK browser

Pacote NPM `@mellostack/signer-agent` (planejado):

```javascript
const agent = await MellostackAgent.connect({ timeoutMs: 3000 });
if (!agent) { /* prompt download instalador */ }
const certs = await agent.listCertificates();
const signedPdf = await agent.signPdf({ certificateId: certs[0].id, pdfBytes, pin });
```

---

## Configuração (integrador — não usuário final)

Arquivo `%ProgramData%\MelloStack\signer-agent\config.json`:

```json
{
  "listenPort": 9180,
  "allowedOrigins": [
    "https://app.exemplo-cliente.com.br",
    "http://localhost:5173"
  ],
  "pkcs11Modules": [
    { "id": "safenet", "configPath": "pkcs11/safenet.conf", "enabled": true },
    { "id": "dxsafe", "configPath": "pkcs11/dxsafe.conf", "enabled": true }
  ],
  "requireUserConsent": true,
  "sessionPinTtlSeconds": 300
}
```

Em corporações: distribuir via **GPO/MDM** — usuário final só executa o instalador.

---

## Estrutura no monorepo (planejada)

```text
mellostack-signer-local/     # LocalKeyProvider, PKCS#11, PKCS#12
apps/signer-agent/           # REST + tray + JPackage (não publicado Maven Central)
packages/signer-agent-js/    # Cliente browser NPM
docs/openapi/signer-agent.yaml
```

O SDK Maven (`mellostack-signer-sdk`) permanece focado em nuvem; `mellostack-signer-local` é dependência do agente.

---

## Comparação: legado vs MelloStack Agent

| Aspecto | Agente legado (CryptoAPI global) | MelloStack Signer Agent |
| :--- | :--- | :--- |
| SafeNet + dxSafe juntos | Frequentemente **incompatível** | **Compatível** (módulos isolados) |
| Formato | CAdES-BES | **PAdES V12** |
| Plataforma | Windows only | Windows + Linux + macOS (roadmap) |
| Produto | Vertical específico | **Horizontal** — qualquer integrador |
| Core | Duplicado | **Mesmo SDK** |

---

## Referências

- [PSC Providers (nuvem)](PSC_PROVIDERS.md)
- [Segurança](SECURITY.md)
- [Portal demo](../apps/README.md)
- Verificador ITI: https://www.gov.br/iti/pt-br/assuntos/repositorio/verificador-de-conformidade
