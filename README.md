# MelloStack Signer

[![CI](https://github.com/ivanmmello/mellostack-signer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ivanmmello/mellostack-signer/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![Maven Central](https://img.shields.io/maven-central/v/com.mellostack.signer/mellostack-signer-sdk?label=Maven%20Central)](https://central.sonatype.com/artifact/com.mellostack.signer/mellostack-signer-sdk)

**ICP-Brasil Cloud Signer SDK** — biblioteca Java open source para assinatura digital qualificada em nuvem conforme a **Cadeia V12 da ICP-Brasil**.

O documento do cliente **nunca** é enviado ao PSC. Apenas o hash SHA-256/384 gerado localmente é transmitido para assinatura remota.

## Módulos

| Módulo | Descrição |
| :--- | :--- |
| `mellostack-signer-core` | PDF, ByteRange, hash, PKCS#7/CMS e contrato `PSCProvider` |
| `mellostack-signer-providers` | Adaptadores OAuth2/CSC (Bird ID, Remote ID, VIDaaS, SAFEID) |
| `mellostack-signer-validator` | ACT, CRL/OCSP e conformidade DOC-ICP |
| `mellostack-signer-sdk` | Fachada unificada — artefato para consumo via Maven/Gradle |

## Requisitos

- Java 17+
- Maven 3.9+

## Build

```bash
mvn clean verify
```

## Dependência Maven

```xml
<dependency>
    <groupId>com.mellostack.signer</groupId>
    <artifactId>mellostack-signer-sdk</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Quick Start

```java
import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;

CloudSigner signer = new CloudSigner(birdIdProvider);

SignatureOptions options = SignatureOptions.builder()
        .withUserAccessToken(tokenOAuth2Usuario)
        .withReason("Assinatura do Contrato")
        .withLocation("São Paulo - SP")
        .withTimestamp(true)
        .withVisibleSignature(false)
        .build();

byte[] pdfSignedBytes = signer.signPdf(pdfBytesOriginal, options);
```

## Estrutura do repositório

```
mellostack-signer/
├── mellostack-signer-core/
├── mellostack-signer-providers/
├── mellostack-signer-validator/
├── mellostack-signer-sdk/
└── apps/                    # Portal demo (homologação — Fase 4.4)
```

## Documentação

- [Documentação técnica V12](Documentacao_ICP_Brasil_Cloud_Signer_V12.md)
- [Controle de desenvolvimento](controle_desenvolvimento_signer.md)
- [Arquitetura de drivers PSC](docs/PSC_PROVIDERS.md)
- [Versionamento (SemVer)](docs/VERSIONING.md)
- [Setup GitHub](docs/GITHUB_SETUP.md)
- [Publicação Maven Central](docs/MAVEN_CENTRAL.md)
- [Guia de contribuição](CONTRIBUTING.md)
- [Código de conduta](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)

## Licença

Apache License 2.0 — veja [LICENSE](LICENSE).
