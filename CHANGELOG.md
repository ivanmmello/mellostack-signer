# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Versionamento Semântico](docs/VERSIONING.md).

## [Unreleased]

### Added

- N/A

### Changed

- N/A

## [1.0.0] — 2026-07-31

Primeira release estável (MVP) — assinatura PAdES ICP-Brasil Cadeia V12 em nuvem.

### Added

- Monorepo Maven `mellostack-signer` com módulos `core`, `providers`, `validator` e `sdk`
- Interface `PSCProvider` para drivers plugáveis de PSC (Bird ID, Remote ID, VIDaaS, SAFEID)
- Fachada `CloudSigner.signPdf()` — fluxo prepare → hash → PSC → CMS → inject
- `SignatureOptions`, `Environment` e contrato de privacidade (somente hash ao PSC)
- Módulo PDF PAdES: ByteRange, preparação, injeção CMS detached
- Módulo crypto: SHA-256/384, `HashPayload`, codificação Base64/Hex
- Módulo CMS/PKCS#7: atributos CAdES/PAdES V12 (`signingCertificateV2`, `messageDigest`, etc.)
- Drivers OAuth2/CSC: Bird ID, Remote ID (Certisign), VIDaaS, SAFEID
- Validator: ACT (RFC 3161), CRL/OCSP, DOC-ICP-15, LTV, `SignatureValidator`
- Testes: 124+ unitários, golden file PAdES, homologação Bird ID (opt-in)
- Exemplos executáveis em `examples/pades-signing`
- CI (GitHub Actions), JaCoCo 60%, perfil `-Prelease` para Maven Central
- Documentação: README, PSC providers, testing, Maven Central, JavaDoc agregado (`-Pdocs`)

### Security

- Documento do cliente nunca é enviado ao PSC — apenas hash do ByteRange

## [1.0.0-SNAPSHOT] — 2026-07-30

Versão de desenvolvimento inicial (Fase 0). API ainda não funcional para assinatura PAdES em produção.

[Unreleased]: https://github.com/ivanmmello/mellostack-signer/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ivanmmello/mellostack-signer/releases/tag/v1.0.0
[1.0.0-SNAPSHOT]: https://github.com/ivanmmello/mellostack-signer/releases/tag/v1.0.0-SNAPSHOT
