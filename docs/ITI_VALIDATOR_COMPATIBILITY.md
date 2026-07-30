# Compatibilidade com Validadores ITI

Este documento descreve como o **MelloStack Signer** se alinha às exigências do ITI para assinaturas PAdES ICP-Brasil V12 e como pré-validar documentos antes da entrega ao usuário final.

## Referências normativas

| Documento | Escopo |
| :--- | :--- |
| **DOC-ICP-15** | Políticas de assinatura digital ICP-Brasil (algoritmos, atributos, cadeia) |
| **Verificador de Conformidade ITI** | Ferramenta oficial para validação de assinaturas ICP-Brasil |
| **RFC 3161** | Carimbo do tempo (ACT) para PAdES-T |
| **RFC 6960 / X.509 CRL** | Revogação online (OCSP) e offline (CRL) |

## O que o SDK garante

### Assinatura (módulo `core` + `sdk`)

- Digest **SHA-256** ou **SHA-384** (família SHA-2)
- Chaves **RSA ≥ 2048 bits** (validadas na política DOC-ICP-15)
- Atributos assinados CAdES/PAdES: `contentType`, `messageDigest`, `signingTime`, `signingCertificateV2`
- Envelope CMS detached (`adbe.pkcs7.detached`) compatível com Adobe PAdES
- Cadeia de certificados embutida no PKCS#7 quando fornecida pelo PSC

### Carimbo do tempo (PAdES-T)

- Atributo não assinado `id-aa-signatureTimeStampToken` via `CmsTimestampEnhancer`
- Integração opcional em `CloudSigner(PSCProvider, TimestampAuthority)` com `withTimestamp(true)`

### Revogação e LTV (módulo `validator`)

- Consulta **OCSP** (preferencial) e fallback **CRL**
- Cache TTL configurável (`RevocationResponseCache`)
- Embutimento de dados LTV no CMS via `CmsLtvEnhancer` (`id-aa-ets-revocationValues`)

## Pré-validação local antes da entrega

Recomendado para aplicações host (ERP, jurídico, SaaS) validarem o PDF **antes** de disponibilizá-lo ao usuário:

```java
import org.icpbrasil.signer.validator.SignatureValidator;
import org.icpbrasil.signer.validator.pades.PadesValidationResult;

byte[] signedPdf = cloudSigner.signPdf(pdfBytes, options);

PadesValidationResult result = SignatureValidator.validateSignedPdf(signedPdf);
if (!result.isValid()) {
    throw new IllegalStateException("Assinatura não conforme: " + result.policyResult().violations());
}

// Opcional: revogação online antes da entrega
SignatureValidator.validateSignedPdf(
    signedPdf,
    issuerCertificate,
    CertificateRevocationValidator.builder().build()
);
```

### O que `validateSignedPdf` verifica

1. Estrutura PAdES legível (PDFBox)
2. Integridade criptográfica do CMS sobre o conteúdo assinado (`ByteRange`)
3. Conformidade **DOC-ICP-15**: RSA ≥ 2048, SHA-2, atributos obrigatórios
4. Presença de carimbo do tempo e dados LTV (quando aplicável) — informativo no resultado

## Validação de longo prazo (LTV)

Após assinar (e opcionalmente carimbar), a aplicação host pode embutir evidências de revogação:

```java
import org.icpbrasil.signer.validator.cms.CmsLtvEnhancer;
import org.icpbrasil.signer.validator.cms.LtvRevocationDataCollector;

LtvRevocationDataCollector collector = new LtvRevocationDataCollector(new JavaRevocationHttpClient());
LtvRevocationData ltvData = collector.collect(signerCertificate, certificateChain);
byte[] cmsWithLtv = CmsLtvEnhancer.enhance(cmsBytes, ltvData);
// Reinjetar cmsWithLtv no PDF preparado
```

## Verificador de Conformidade ITI

O **Verificador de Conformidade** do ITI é a referência oficial para homologação. O MelloStack Signer foi projetado para produzir assinaturas que atendam:

| Requisito ITI | Implementação MelloStack |
| :--- | :--- |
| Algoritmos SHA-2 | `DigestAlgorithm.SHA256` / `SHA384` |
| RSA ≥ 2048 bits | `DocIcp15PolicyValidator` |
| Atributos PAdES | `CmsEnvelopeAssembler` |
| ACT (PAdES-T) | `CmsTimestampEnhancer` |
| Evidências de revogação (LTV) | `CmsLtvEnhancer` |

> **Homologação:** Execute testes ponta a ponta com certificados reais de homologação do PSC e valide o PDF resultante no [Verificador de Conformidade ITI](https://www.gov.br/iti/pt-br/assuntos/repositorio/verificador-de-conformidade).

## Limitações conhecidas (MVP 1.0.0)

- Validação local não substitui o Verificador ITI em auditorias oficiais
- LTV embute CRL/OCSP no CMS; DSS PDF 2.0 nativo não está implementado nesta versão
- Cadeia ICP-Brasil V12 completa depende do PSC retornar intermediários via `PSCProvider.getCertificateChain()`
