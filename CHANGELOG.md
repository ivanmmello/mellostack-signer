# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Versionamento Semântico](docs/VERSIONING.md).

## [Unreleased]

### Added

- Monorepo Maven `mellostack-signer` com módulos `core`, `providers`, `validator` e `sdk`
- Interface `PSCProvider` para drivers plugáveis de PSC
- Fachada `CloudSigner`, `SignatureOptions`, `SignatureResult` e `Environment`
- `CloudSigner.signPdf()` — fluxo completo prepare → hash → PSC → CMS → inject
- `PSCProvider.getSignerCertificate()` para montagem do envelope CMS
- Módulo PDF PAdES: `PadesSignaturePreparer`, `PadesSignatureInjector`, `ByteRangeSupport`, `PdfIntegrityValidator`
- Módulo crypto: `DocumentDigestCalculator`, `HashPayload`, `EncodingUtils` (Base64/Hex para APIs PSC)
- Módulo CMS/PKCS#7: `CmsEnvelopeAssembler`, `CmsAssemblyRequest`, atributos PAdES (`signingCertificateV2`, `messageDigest`, etc.)
- Testes unitários PAdES no `mellostack-signer-core` (27 testes)
- Módulo providers: `SecureHttpClient`, OAuth2 PKCE, `BirdIdProvider`, `BirdIdOAuth2Support`
- Cliente ITI genérico: `ItiCloudPscApiClient`, `ItiCloudPscOAuth2Support` (compartilhado Bird ID / Remote ID)
- Driver Certisign: `RemoteIdProvider`, `RemoteIdProviderBuilder`, `RemoteIdOAuth2Support`
- Driver Valid: `VidaasProvider`, `VidaasProviderBuilder`, `VidaasOAuth2Support`, fluxo push
- Driver Safeweb: `SafeIdProvider`, `SafeIdProviderBuilder`, `SafeIdOAuth2Support`
- Testes unitários providers (Bird ID + Remote ID + infra HTTP/OAuth)
- Documentação de segurança: `docs/SECURITY.md`
- Documentação técnica V12, controle de desenvolvimento e governança open source
- Testes unitários iniciais em `CloudSignerTest` (validação de contrato)
- GitHub Actions CI (build, testes, Enforcer, JaCoCo) e workflow Release
- Dependabot (Maven + GitHub Actions), perfil Maven `-Prelease` para Maven Central
- Badges no README, docs `GITHUB_SETUP.md` e `MAVEN_CENTRAL.md`

### Changed

- N/A

### Deprecated

- N/A

### Removed

- N/A

### Fixed

- N/A

### Security

- N/A

## [1.0.0-SNAPSHOT] — 2026-07-30

Versão de desenvolvimento inicial (Fase 0). API ainda não funcional para assinatura PAdES em produção.

[Unreleased]: https://github.com/ivanmmello/mellostack-signer/compare/v1.0.0-SNAPSHOT...HEAD
[1.0.0-SNAPSHOT]: https://github.com/ivanmmello/mellostack-signer/releases/tag/v1.0.0-SNAPSHOT
