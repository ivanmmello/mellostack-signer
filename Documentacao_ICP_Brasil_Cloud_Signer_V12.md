# ICP-Brasil Cloud Signer SDK (v12)
> **Documentação Técnica & Arquitetura de Módulo Plugável Java (JAR) para Assinatura em Nuvem**

| Informação | Detalhe |
| :--- | :--- |
| **Nome do Projeto** | `icpbrasil-cloud-signer-sdk` |
| **Linguagem & Runtime** | Java 17+ / Jakarta EE / Spring Boot Compatible |
| **Padrão de Assinatura** | PAdES / CAdES / XAdES — Cadeia V12 ICP-Brasil |
| **Licença** | Apache License 2.0 (Open Source) |

---

## 1. Visão Geral e Objetivos do Projeto

O **ICP-Brasil Cloud Signer SDK** é uma biblioteca *open source* em Java projetada para ser acoplada diretamente como uma dependência JAR em qualquer sistema legado ou moderno (Spring Boot, Quarkus, Jakarta EE, Android Server, etc.) [cite: 2]. Seu propósito principal é abstrair toda a complexidade técnica envolvida na emissão de assinaturas digitais qualificadas em nuvem sob a nova **Cadeia V12 da ICP-Brasil** [cite: 2].

Com a migração progressiva da infraestrutura de chaves públicas brasileira do modelo tradicional A3 físico (tokens e smartcards) para o modelo de **Certificado em Nuvem** gerido por Prestadores de Serviço de Confiança (PSCs) credenciados pelo ITI, desenvolvedores enfrentam desafios recorrentes na implementação dos fluxos de autorização OAuth2, cálculo do `ByteRange` de PDFs, injeção da estrutura PKCS#7 e conformidade com carimbos do tempo e políticas de validação a longo prazo (LTV) [cite: 2].

> 📌 **DIRETRIZES FUNDAMENTAIS DE DESIGN**
> * **Privacidade Total dos Dados:** O documento do cliente NUNCA é enviado para o PSC. Apenas o hash SHA-256 / SHA-384 gerado localmente pelo JAR é transmitido para assinatura [cite: 2].
> * **Zero Boilerplate:** O desenvolvedor precisa de menos de 10 linhas de código para autenticar o usuário, enviar o hash para o PSC e obter o documento assinado [cite: 2].
> * **Multi-PSC Plugável:** Arquitetura baseada em drivers que permite alternar entre Soluti (BirdID), Certisign (RemoteID), Valid (VIDaaS) e Safeweb (SAFEID) sem alterar a regra de negócio do sistema [cite: 2].

---

## 2. Arquitetura e Design do Módulo JAR

A biblioteca é dividida em três módulos lógicos internos, garantindo baixo acoplamento e altíssima extensibilidade [cite: 2]:

* **Módulo Core (`mellostack-signer-core`):** Responsável pela manipulação de arquivos PDF (via Apache PDFBox), criação de contêineres de assinatura vazia (`/ByteRange`), geração de hash de alta performance e montagem do envelope PKCS#7 / CMS com inclusão da cadeia X.509 V12 [cite: 2].
* **Módulo Providers (`mellostack-signer-providers`):** Contém as implementações dos adaptadores OAuth2 / CSC (*Cloud Signature Consortium*) para cada PSC credenciado no Brasil [cite: 2].
* **Módulo Validation & Timestamp (`mellostack-signer-validator`):** Responsável pela comunicação com Autoridades de Carimbo do Tempo (ACT), verificação de revogação via CRL/OCSP e suporte às políticas de assinatura DOC-ICP do ITI [cite: 2].

### Estrutura do Repositório

| Caminho | Tipo | Distribuição |
| :--- | :--- | :--- |
| `mellostack-signer-core/` | Módulo Maven | Publicado (Maven Central) |
| `mellostack-signer-providers/` | Módulo Maven | Publicado (Maven Central) |
| `mellostack-signer-validator/` | Módulo Maven | Publicado (Maven Central) |
| `mellostack-signer-sdk/` | Módulo Maven (fachada) | Publicado (Maven Central) |
| `apps/signer-demo-api/` | Spring Boot REST | **Apenas homologação** — simula backend de produção |
| `apps/signer-demo-web/` | React + Vite | **Apenas homologação** — simula tela do usuário final |

### Fluxo de Execução da Assinatura

O ciclo de vida de uma assinatura digital utilizando o SDK ocorre em 5 etapas sequenciais [cite: 2]:

```text
┌────────────────┐     ┌─────────────────────┐     ┌──────────────────────┐
│ Aplicação Host │     │ Cloud Signer (JAR)  │     │   PSC (Nuvem / HSM)  │
└───────┬────────┘     └──────────┬──────────┘     └──────────┬───────────┘
        │                         │                           │
        │ 1. Solicita Assinatura  │                           │
        ├────────────────────────►│                           │
        │                         │ 2. Prepara PDF & Hash     │
        │                         ├────────┐                  │
        │                         │        │ SHA-256          │
        │                         │◄───────┘                  │
        │                         │                           │
        │                         │ 3. Envia Hash + Token OTP │
        │                         ├──────────────────────────►│
        │                         │                           │
        │                         │ 4. Retorna Assinatura     │
        │                         │    Criptografada (Raw)    │
        │                         │◄──────────────────────────┤
        │                         │                           │
        │                         │ 5. Monta PAdES + ACT + V12│
        │                         ├────────┐                  │
        │                         │        │ Inject PKCS#7    │
        │                         │◄───────┘                  │
        │ Retorna PDF Assinado    │                           │
        │◄────────────────────────┤                           │
┌───────┴────────┐     ┌──────────┴──────────┐     ┌──────────┴───────────┐
│ Aplicação Host │     │ Cloud Signer (JAR)  │     │   PSC (Nuvem / HSM)  │
└────────────────┘     └─────────────────────┘     └──────────────────────┘
```

---

## 3. Configuração e Dependência Maven / Gradle

Para utilizar a biblioteca no projeto Java, adicione a seguinte dependência no arquivo `pom.xml` [cite: 2]:

```xml
<dependency>
    <groupId>com.mellostack.signer</groupId>
    <artifactId>mellostack-signer-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

Se estiver utilizando Gradle (Kotlin / Groovy) [cite: 2]:

```groovy
implementation 'com.mellostack.signer:mellostack-signer-sdk:1.0.0'
```

---

## 4. Guia de Uso Prático (Exemplos de Código)

### Passo 1: Instanciação do Provedor de PSC

Cada PSC possui configurações de credenciais de aplicação (Client ID e Client Secret) fornecidas após o credenciamento de parceiro [cite: 2]:

```java
// Exemplo de configuração do driver BirdID (Soluti)
PSCProvider birdIdProvider = new BirdIdProviderBuilder()
        .withClientId("SEU_CLIENT_ID")
        .withClientSecret("SEU_CLIENT_SECRET")
        .withEnvironment(Environment.HOMOLOGATION) // ou PRODUCTION
        .build();
```

### Passo 2: Executando a Assinatura PAdES no PDF

Com o token OAuth2 obtido do usuário final (via fluxo de autorização ou OTP do aplicativo do PSC), executa-se o processo de assinatura [cite: 2]:

```java
import org.icpbrasil.signer.core.CloudSigner;
import org.icpbrasil.signer.model.SignatureOptions;
import org.icpbrasil.signer.model.SignatureResult;
import java.nio.file.Files;
import java.nio.file.Paths;

// 1. Instancia a fachada de assinatura
CloudSigner signer = new CloudSigner(birdIdProvider);

// 2. Carrega o documento PDF original
byte[] pdfBytesOriginal = Files.readAllBytes(Paths.get("contrato.pdf"));

// 3. Define as opções de assinatura (Cadeia V12 + Carimbo do Tempo)
SignatureOptions options = SignatureOptions.builder()
        .withUserAccessToken(tokenOAuth2Usuario)
        .withReason("Assinatura do Contrato de Prestação de Serviços")
        .withLocation("São Paulo - SP")
        .withTimestamp(true) // Requer Autoridade de Carimbo do Tempo (ACT)
        .withVisibleSignature(false) // Assinatura invisível no layout PDF
        .build();

// 4. Assina o documento
byte[] pdfSignedBytes = signer.signPdf(pdfBytesOriginal, options);

// 5. Salva o PDF final com conformidade ICP-Brasil V12
Files.write(Paths.get("contrato_assinado_v12.pdf"), pdfSignedBytes);
```

---

## 5. Tabela de Compatibilidade com PSCs Nacionais

A biblioteca possui suporte nativo e padronizado aos principais Prestadores de Serviço de Confiança (PSCs) em operação no ecossistema da ICP-Brasil [cite: 2]:

| Prestador (PSC) | Nome Comercial | Protocolo API | Suporte V12 / ACT |
| :--- | :--- | :--- | :--- |
| **Soluti** | Bird ID | OAuth2 / REST CSC | Sim / Nativo |
| **Certisign** | Remote ID | OAuth2 / REST Custom | Sim / Nativo |
| **Valid** | VIDaaS | OpenID Connect / REST | Sim / Nativo |
| **Safeweb** | SAFEID | OAuth2 / REST | Sim / Nativo |

---

## 6. Conformidade ICP-Brasil V12 e Validação LTV

A versão 12 da estrutura de chaves públicas brasileira estabeleceu atualizações de segurança fundamentais, estipulando algoritmos de digest mais robustos (família SHA-2) e chaves RSA de no mínimo 2048 bits [cite: 2]. O SDK atende integralmente às exigências publicadas no documento **DOC-ICP-15** do ITI [cite: 2]:

* **Injeção de Atributos Assinados:** Inclusão mandatória dos atributos CAdES/PAdES: `contentType`, `messageDigest`, `signingTime` e `signingCertificateV2` contendo o hash do certificado do signatário [cite: 2].
* **Validação de Cadeia em Nuvem:** Inclusão automática dos certificados intermediários da V12 e raiz da ICP-Brasil no pacote PKCS#7/CMS [cite: 2].
* **Suporte a Carimbo do Tempo (ACT):** Injeção do selo temporal recebido de uma Autoridade de Carimbo do Tempo credenciada, garantindo irrefutabilidade sobre a data/hora exata do ato de assinatura [cite: 2].

---

## 7. Portal de Demonstração — Simulação do Host em Produção

> ⚠️ **Escopo exclusivo de homologação.** O portal web **não faz parte do artefato JAR** publicado no Maven Central. Ele existe apenas para testar o SDK durante o desenvolvimento, simulando o fluxo que um **sistema cliente em produção** (ERP, jurídico, SaaS, portal corporativo) executará quando o usuário final solicitar uma assinatura digital em nuvem.

### 7.1 Objetivo

Quando um usuário clica em **"Assinar documento"** no sistema de produção, a aplicação host orquestra OAuth2, envia o PDF ao SDK, repassa o hash ao PSC e devolve o arquivo assinado. O portal demo reproduz exatamente esse papel de **Aplicação Host** — permitindo validar ponta a ponta o SDK, os drivers de PSC e a conformidade V12 sem depender de um produto MelloStack já integrado.

### 7.2 Arquitetura do Portal Demo

```text
┌─────────────────────┐     ┌──────────────────────────┐     ┌─────────────────────┐
│  signer-demo-web    │     │   signer-demo-api        │     │  Cloud Signer (JAR) │
│  (React + Vite)     │     │   (Spring Boot REST)     │     │  + PSC (Homologação)│
└──────────┬──────────┘     └────────────┬─────────────┘     └──────────┬──────────┘
           │                             │                              │
           │ 1. Upload PDF + opções      │                              │
           ├────────────────────────────►│                              │
           │                             │ 2. Inicia OAuth2 / PKCE      │
           │                             ├─────────────────────────────►│ PSC
           │ 3. Redirect OAuth (usuário) │                              │
           ◄─────────────────────────────┤                              │
           │                             │ 4. Callback + token          │
           ├────────────────────────────►│                              │
           │                             │ 5. signPdf() via SDK         │
           │                             ├─────────────────────────────►│
           │                             │ 6. PDF assinado              │
           │ 7. Download do PDF assinado │◄─────────────────────────────┤
           ◄─────────────────────────────┤                              │
```

| Componente | Tecnologia | Função |
| :--- | :--- | :--- |
| **`signer-demo-web`** | React 19 + Vite + TypeScript | Interface que simula a tela do usuário final ("Solicitar assinatura") |
| **`signer-demo-api`** | Spring Boot 3 + Java 17 | API REST que consome o SDK — mesmo padrão de integração que sistemas em produção |
| **`icpbrasil-cloud-signer-sdk`** | JAR (dependência Maven) | Biblioteca assinada; lógica de negócio real, não mock |

### 7.3 Fluxo Simulado (Experiência do Usuário Final)

1. **Seleção do PSC** — Usuário escolhe o prestador (Bird ID, Remote ID, VIDaaS ou SAFEID) e o ambiente (Homologação / Produção).
2. **Upload do documento** — Arrastar ou selecionar um PDF a ser assinado (permanece no servidor demo; apenas o hash segue ao PSC).
3. **Autenticação OAuth2** — Redirect para o PSC; usuário autoriza com app/credenciais do certificado em nuvem.
4. **Confirmação OTP** — Quando exigido pelo PSC, informar código do aplicativo móvel.
5. **Opções de assinatura** — Motivo, local, assinatura visível/invisível, carimbo do tempo (ACT).
6. **Processamento** — API invoca `CloudSigner.signPdf()`; barra de progresso e logs de etapa (hash → PSC → PKCS#7 → PAdES).
7. **Download e validação** — PDF assinado disponível para download; exibição de metadados (certificado, data, cadeia V12).

### 7.4 Telas Previstas

| Tela | Descrição |
| :--- | :--- |
| **Início / Nova assinatura** | Upload PDF, seleção de PSC e ambiente |
| **Autorização** | Redirect OAuth2 + callback; estado de sessão seguro |
| **Confirmação OTP** | Input de código quando o PSC exigir |
| **Opções avançadas** | Reason, location, visible signature, timestamp |
| **Resultado** | Preview de status, download do PDF assinado, dados do certificado |
| **Histórico de testes** | Lista local (sessão/dev) das assinaturas de homologação executadas |

### 7.5 Regras de Escopo

* O portal demo **não é distribuído** como produto; vive em `apps/signer-demo-web` e `apps/signer-demo-api` no repositório.
* Credenciais de PSC (Client ID / Secret) ficam em variáveis de ambiente — nunca commitadas.
* Em produção real, cada sistema MelloStack (ou cliente externo) implementa sua própria UI; o SDK permanece agnóstico a framework front-end.
* O demo serve como **referência de integração** documentada: o código da API espelha o que um backend Spring Boot em produção faria.

---

## 8. Roadmap e Próximos Passos do Projeto

Como projeto de código aberto mantido pela comunidade dev, as seguintes metas estão mapeadas para as futuras releases [cite: 2]:

* **Release 1.1.0:** Suporte nativo para assinatura em lote (*Batch Signing*) enviando hashes múltiplos em uma única requisição autorizada via OTP [cite: 2].
* **Release 1.2.0:** Módulo CLI (*Command Line Interface*) em GraalVM Native Image para assinatura rápida via linha de comando no terminal [cite: 2].
* **Release 1.3.0:** Adição do suporte a Assinatura de Código XML (XAdES) para emissão de Notas Fiscais Eletrônicas (NF-e) com certificado em nuvem [cite: 2].
* **Portal Demo (paralelo ao MVP):** Aplicação web + API Spring Boot para homologação ponta a ponta — simula o fluxo de produção quando o usuário solicita assinatura; **não compõe o JAR publicado**.
