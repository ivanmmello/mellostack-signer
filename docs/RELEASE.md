# Release 1.0.0 — MVP

Checklist e procedimento para publicar a primeira release estável no Maven Central.

## Critérios de aceite (Fase 4.3)

| Critério | Status | Evidência |
| :--- | :---: | :--- |
| PAdES funcional com Bird ID (homologação) | Manual | `PscHomologationIT#birdIdSignsPdfInHomologation` |
| Cadeia V12 + atributos CAdES/PAdES | Automático | `PadesSigningGoldenFileIT`, `DocIcp15PolicyValidator` |
| Testes unitários + cobertura ≥ 60% | Automático | `mvn -Pci clean verify` |
| Artefato publicável no Maven Central | CI | workflow `Release` + perfil `-Prelease` |
| Tag GitHub `v1.0.0` | Manual | ver passos abaixo |

## Artefato Maven

```xml
<dependency>
    <groupId>com.mellostack.signer</groupId>
    <artifactId>mellostack-signer-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

Portal: https://central.sonatype.com/artifact/com.mellostack.signer/mellostack-signer-sdk

## Pré-release (local)

### 1. Validar build

```bash
mvn -Pci clean verify "-Dspotbugs.skip=true"
```

### 2. Homologação Bird ID (opcional, recomendado)

Requer credenciais reais de homologação:

```bash
# PowerShell
$env:PSC_HOMOLOGATION_ENABLED = "true"
$env:BIRDID_CLIENT_ID = "..."
$env:BIRDID_CLIENT_SECRET = "..."
$env:PSC_ACCESS_TOKEN = "..."

mvn -pl mellostack-signer-sdk test "-Dgroups=integration" "-Dtest=PscHomologationIT"
```

### 3. Confirmar versão `1.0.0` (sem `-SNAPSHOT`)

```bash
mvn help:evaluate -Dexpression=project.version -q -DforceStdout
# deve imprimir: 1.0.0
```

## Publicação

### Pré-requisitos GitHub

Secrets configurados (Settings → Secrets → Actions):

| Secret | Uso |
| :--- | :--- |
| `CENTRAL_USERNAME` | Token Sonatype Central Portal |
| `CENTRAL_PASSWORD` | Token Sonatype Central Portal |
| `GPG_PRIVATE_KEY` | Assinatura dos artefatos |
| `GPG_PASSPHRASE` | Passphrase GPG |

Namespace `com.mellostack.signer` verificado no [Central Portal](https://central.sonatype.com/).

### Passos Git

```bash
git checkout develop
git pull origin develop

# merge para main (via PR recomendado)
git checkout main
git merge develop

git commit -am "chore: release 1.0.0"   # se ainda houver alterações pendentes
git tag -a v1.0.0 -m "Release 1.0.0 — MVP PAdES ICP-Brasil V12"
git push origin main v1.0.0
```

O push da tag `v1.0.0` dispara `.github/workflows/release.yml`, que:

1. Executa `mvn -Prelease clean deploy`
2. Assina artefatos com GPG
3. Publica no Maven Central (revisão manual no portal se `autoPublish=false`)
4. Cria GitHub Release com JARs anexados

### Deploy manual (alternativa)

```bash
mvn -Prelease clean deploy "-DskipTests"
```

Requer `~/.m2/settings.xml` configurado — ver [MAVEN_CENTRAL.md](MAVEN_CENTRAL.md).

## Pós-release

1. Aprovar/publicar o bundle no Sonatype Central Portal (se `autoPublish=false`)
2. Confirmar badge Maven Central no README
3. Retomar desenvolvimento em `develop` com versão `1.0.1-SNAPSHOT` (ou `1.1.0-SNAPSHOT` para próxima minor)

```bash
git checkout develop
# atualizar pom.xml para 1.0.1-SNAPSHOT
git commit -am "chore: prepare next development iteration 1.0.1-SNAPSHOT"
git push origin develop
```

## Notas da release

### Destaques

- Assinatura PAdES qualificada em nuvem (Cadeia ICP-Brasil V12)
- Drivers: Bird ID, Remote ID, VIDaaS, SAFEID
- Privacidade: PDF nunca sai da aplicação host
- PAdES-T (ACT), validação DOC-ICP-15, CRL/OCSP, LTV

### Limitações conhecidas (1.0.0)

- Portal demo (Fase 4.4) ainda não incluído
- Batch signing, CLI e XAdES/NF-e planejados para 1.1+
