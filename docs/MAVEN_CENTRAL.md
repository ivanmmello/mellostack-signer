# Publicação no Maven Central

Guia para publicar o artefato `com.mellostack.signer:mellostack-signer-sdk` no Maven Central via Sonatype.

## Pré-requisitos

1. Conta no [Sonatype Central Portal](https://central.sonatype.com/)
2. Namespace `com.mellostack.signer` verificado (DNS TXT ou GitHub org verification)
3. Par de chaves GPG para assinar releases
4. Repositório GitHub configurado com secrets (ver [GITHUB_SETUP.md](GITHUB_SETUP.md))

## Namespace

O `groupId` do projeto é:

```text
com.mellostack.signer
```

Verifique a propriedade do namespace no Central Portal **antes** do primeiro deploy.

## Artefatos publicados

| Artefato | Descrição |
| :--- | :--- |
| `mellostack-signer-core` | Core PDF/hash/PKCS#7 |
| `mellostack-signer-providers` | Drivers PSC |
| `mellostack-signer-validator` | ACT, CRL/OCSP |
| `mellostack-signer-sdk` | **Dependência recomendada** (fachada + transitivas) |

Cada módulo publica: `.jar`, `-sources.jar`, `-javadoc.jar`, `.pom` assinados.

## Configuração local (`~/.m2/settings.xml`)

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>SEU_TOKEN_CENTRAL</username>
      <password>SEU_TOKEN_CENTRAL</password>
    </server>
  </servers>

  <profiles>
    <profile>
      <id>release</id>
      <properties>
        <gpg.passphrase>SUA_PASSPHRASE</gpg.passphrase>
      </properties>
    </profile>
  </profiles>
</settings>
```

## Deploy manual (teste)

```bash
# Snapshot (develop)
mvn clean deploy -Prelease

# Release (versão sem -SNAPSHOT, tag vX.Y.Z)
mvn clean deploy -Prelease -DskipTests
```

## Deploy automático (CI)

O workflow `.github/workflows/release.yml` executa em push de tags `v*`:

1. Compila com perfil `-Prelease`
2. Assina com GPG (secrets)
3. Publica via `central-publishing-maven-plugin`
4. Anexa JARs na GitHub Release

## Consumo após publicação

```xml
<dependency>
    <groupId>com.mellostack.signer</groupId>
    <artifactId>mellostack-signer-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

Portal: https://central.sonatype.com/artifact/com.mellostack.signer/mellostack-signer-sdk

## Troubleshooting

| Erro | Solução |
| :--- | :--- |
| 401 Unauthorized | Verificar `CENTRAL_USERNAME` / `CENTRAL_PASSWORD` nos secrets |
| Namespace not verified | Completar verificação no Central Portal |
| GPG signature failed | Conferir `GPG_PRIVATE_KEY` e `GPG_PASSPHRASE` |
| Javadoc warnings as errors | Corrigir Javadoc ou ajustar `doclint` no pom |

## Referências

- [Central Portal publish guide](https://central.sonatype.org/publish/publish-portal-maven/)
- [VERSIONING.md](VERSIONING.md) — política SemVer do projeto
