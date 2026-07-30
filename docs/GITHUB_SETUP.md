# Setup do repositório GitHub

Guia para publicar o **mellostack-signer** como repositório open source no GitHub.

## 1. Criar o repositório

1. Acesse a organização **mellostack** no GitHub (ou sua conta pessoal).
2. **New repository** → nome: `mellostack-signer`
3. Visibilidade: **Public**
4. **Não** inicializar com README (já existe localmente).
5. Licença: Apache 2.0 (já incluída no projeto).

URL esperada: `https://github.com/ivanmmello/mellostack-signer`

## 2. Inicializar Git local (repositório dedicado)

Se o projeto ainda estiver dentro do monorepo `Saass Modular`, inicialize um repositório **apenas** na pasta do signer:

```bash
cd mellostack-signer
git init
git add .
git commit -m "chore: initial commit — Fase 0 (monorepo Maven + docs)"
```

## 3. Branches

Estratégia **Git Flow simplificado**:

| Branch | Uso |
| :--- | :--- |
| `main` | Produção — releases tagueadas (`vX.Y.Z`) |
| `develop` | Integração contínua — base para PRs |
| `feature/*` | Features isoladas → PR para `develop` |
| `fix/*` | Correções → PR para `develop` |
| `release/*` | Preparação de release → merge em `main` + `develop` |

Comandos iniciais:

```bash
git branch -M main
git checkout -b develop
git push -u origin main
git push -u origin develop
```

Proteção recomendada (Settings → Branches → Rules):

- **main**: exigir PR, status check `CI / Build & Test`, sem push direto
- **develop**: exigir status check `CI / Build & Test`

## 4. Conectar remote e push

```bash
git remote add origin git@github.com:ivanmmello/mellostack-signer.git
git push -u origin main develop
```

## 5. Secrets para release (Maven Central)

Settings → Secrets and variables → Actions:

| Secret | Descrição |
| :--- | :--- |
| `CENTRAL_USERNAME` | Token do [Sonatype Central Portal](https://central.sonatype.com/) |
| `CENTRAL_PASSWORD` | Senha/token do Central Portal |
| `GPG_PRIVATE_KEY` | Chave privada ASCII-armored para assinar artefatos |
| `GPG_PASSPHRASE` | Passphrase da chave GPG |

Detalhes em [MAVEN_CENTRAL.md](MAVEN_CENTRAL.md).

## 6. Verificar CI

Após o primeiro push em `main` ou `develop`:

1. Aba **Actions** → workflow **CI** deve ficar verde.
2. Badge no README atualiza automaticamente.

## 7. Primeira release

Quando a API estiver estável (Fase 4):

```bash
git checkout main
git merge develop
# Atualizar versão no pom.xml (remover -SNAPSHOT)
git commit -am "chore: release 1.0.0"
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin main v1.0.0
```

O workflow **Release** publica no Maven Central e cria GitHub Release.
