# Portal Demo — MelloStack Signer

Ambiente de **homologação ponta a ponta** para testar o SDK — **não é produto** e **não é publicado** no Maven Central.

Simula o que um ERP, jurídico ou SaaS faz quando o usuário clica em **Assinar documento**: upload PDF → OAuth2 PSC → `CloudSigner.signPdf()` → download.

## Estrutura

| App | Stack | Porta |
| :--- | :--- | :---: |
| `signer-demo-api/` | Spring Boot 3 + SDK local | 8096 |
| `signer-demo-web/` | React 19 + Vite + TypeScript | 5173 |

## Pré-requisitos

- Java 17+, Maven 3.9+
- Node.js 20+ e npm
- Credenciais PSC de homologação (Bird ID recomendado para primeiro teste)
- Redirect URI cadastrado no PSC: `http://localhost:8096/api/v1/oauth/callback`

## 1. Build do SDK

Na raiz do monorepo:

```bash
mvn clean install -DskipTests
```

## 2. Configurar credenciais

Copie `apps/.env.example` e exporte as variáveis (ou configure no IDE):

```powershell
$env:PSC_CLIENT_ID = "..."
$env:PSC_CLIENT_SECRET = "..."
$env:PSC_PROVIDER = "birdid"
$env:PSC_ENVIRONMENT = "homologation"
$env:DEMO_OAUTH_REDIRECT_URI = "http://localhost:8096/api/v1/oauth/callback"
$env:DEMO_FRONTEND_URL = "http://localhost:5173"
```

## 3. Subir API demo

```bash
cd apps/signer-demo-api
mvn spring-boot:run
```

Health: http://localhost:8096/health

## 4. Subir front demo

```bash
cd apps/signer-demo-web
npm install
npm run dev
```

Abra http://localhost:5173

## Fluxo

1. Upload PDF + seleção PSC/ambiente  
2. Opções (reason, location, visível, ACT)  
3. **Autorizar no PSC** — OAuth2 + OTP no navegador  
4. Assinatura automática (hash → PSC → CMS → PAdES)  
5. Download + histórico local no navegador  

## API (referência)

| Método | Endpoint |
| :--- | :--- |
| POST | `/api/v1/sign/prepare` (multipart PDF) |
| PUT | `/api/v1/sign/{sessionId}/options` |
| GET | `/api/v1/oauth/authorize?sessionId=` |
| GET | `/api/v1/oauth/callback` |
| POST | `/api/v1/sign/{sessionId}/execute` |
| GET | `/api/v1/sign/{sessionId}/download` |
| GET | `/health` |

## Docker (opcional)

```bash
docker compose -f apps/docker-compose.yml up --build
```

## Alternância de PSC

Altere `PSC_PROVIDER` (`birdid`, `remoteid`, `vidaas`, `safeid`) — a API demo usa a mesma lógica de assinatura; Remote ID exige `PSC_API_BASE_URL`.

> **Aviso:** este portal existe apenas para homologação do SDK open source. Não use em produção nem exponha na internet pública sem hardening adicional.
