# Política de Versionamento (SemVer)

O **MelloStack Signer** segue o [Versionamento Semântico 2.0.0](https://semver.org/lang/pt-BR/).

Formato: **`MAJOR.MINOR.PATCH`** (ex.: `1.2.3`)

Durante o desenvolvimento pré-1.0, versões usam sufixo **`-SNAPSHOT`** (ex.: `1.0.0-SNAPSHOT`).

## Quando incrementar

| Tipo | Incremento | Exemplo | Quando usar |
| :--- | :---: | :--- | :--- |
| **MAJOR** | `X.0.0` | `1.0.0` → `2.0.0` | Breaking change na API pública (`org.icpbrasil.signer.*`) |
| **MINOR** | `0.X.0` | `1.0.0` → `1.1.0` | Nova feature compatível (ex.: driver PSC, batch signing) |
| **PATCH** | `0.0.X` | `1.0.0` → `1.0.1` | Correção de bug compatível com versões anteriores |

## API pública

Considera-se API pública:

- Classes e interfaces em `org.icpbrasil.signer.core`, `.model`, `.provider`, `.validator`
- Assinaturas de métodos públicos e enums expostos
- Comportamento documentado de `CloudSigner.signPdf()`

**Não** é API pública (pode mudar sem major):

- Classes em pacotes `internal` ou `impl` (quando existirem)
- Módulos em `apps/` (portal demo de homologação)
- Detalhes de implementação de drivers PSC

## Pré-1.0.0

Enquanto `MAJOR = 0` ou em `-SNAPSHOT`:

- Breaking changes são permitidos com aviso em `CHANGELOG.md`
- A release `1.0.0` estabiliza o contrato mínimo documentado no README e na documentação técnica

## Releases planejadas

| Versão | Escopo |
| :--- | :--- |
| **1.0.0** | PAdES funcional, ≥1 PSC em homologação, Maven Central |
| **1.1.0** | Batch signing |
| **1.2.0** | CLI GraalVM |
| **1.3.0** | XAdES / NF-e |

## Processo de release

1. Congelar `develop` → branch `release/X.Y.Z`
2. Remover `-SNAPSHOT` do `pom.xml` parent e módulos
3. Atualizar `CHANGELOG.md` (mover `[Unreleased]` → `[X.Y.Z]`)
4. Tag Git anotada: `vX.Y.Z`
5. Publicar no Maven Central
6. Incrementar para `(X.Y.(Z+1))-SNAPSHOT` em `develop`

## Changelog

Toda mudança visível ao consumidor deve ser registrada em [CHANGELOG.md](../CHANGELOG.md), seção `[Unreleased]`, usando categorias:

- **Added**, **Changed**, **Deprecated**, **Removed**, **Fixed**, **Security**

## Coordenadas Maven

```xml
<groupId>com.mellostack.signer</groupId>
<artifactId>mellostack-signer-sdk</artifactId>
<version>X.Y.Z</version>
```

O versionamento é único para todo o monorepo (parent POM); todos os módulos compartilham a mesma versão.
