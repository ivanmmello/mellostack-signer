# Guia de Contribuição

Obrigado por considerar contribuir com o **MelloStack Signer** (ICP-Brasil Cloud Signer SDK).

## Como contribuir

1. **Fork** o repositório e crie uma branch a partir de `develop`:
   ```bash
   git checkout develop
   git checkout -b feature/minha-contribuicao
   ```
2. Implemente a alteração com **testes unitários** quando aplicável (especialmente em `core` e `providers`).
3. Garanta que o build passa:
   ```bash
   mvn clean verify
   ```
4. Abra um **Pull Request** para `develop` descrevendo o problema, a solução e como testar.

## Padrões de código

- **Java 17+** — use `release` 17; evite APIs preview.
- **Encoding UTF-8** em todos os arquivos fonte.
- Pacotes públicos da API: `org.icpbrasil.signer.*`
- Siga o estilo existente: classes `final` quando possível, builders para opções, validação explícita de argumentos.
- Comentários apenas para lógica não óbvia (ByteRange, PKCS#7, fluxos OAuth2).
- Não commite credenciais, `.env`, certificados `.p12`/`.pfx` ou secrets de PSC.

## Estrutura de módulos

| Módulo | Responsabilidade |
| :--- | :--- |
| `mellostack-signer-core` | PDF, hash, PKCS#7, interface `PSCProvider` |
| `mellostack-signer-providers` | Implementações de drivers PSC |
| `mellostack-signer-validator` | ACT, CRL/OCSP, LTV |
| `mellostack-signer-sdk` | Fachada `CloudSigner` — artefato publicável |

Alterações de API pública devem ser discutidas em issue antes de breaking changes.

## Testes

- **JUnit 5** para testes unitários.
- Escreva testes junto com a feature (Fase 1 em diante), não depois.
- `core`: golden files PDF para ByteRange e hash.
- `providers`: mocks HTTP/OAuth2; integração real apenas em homologação.

## Commits

Prefira mensagens claras em português ou inglês, no imperativo:

```
feat(core): implementar cálculo de ByteRange PAdES
fix(providers): corrigir refresh token Bird ID
docs: atualizar guia de PSC providers
test(core): adicionar testes SHA-256 sobre ByteRange
```

## Pull Requests

- Uma preocupação por PR (feature ou fix isolado).
- Atualize `CHANGELOG.md` na seção `[Unreleased]` quando a mudança for visível ao consumidor.
- Atualize `controle_desenvolvimento_signer.md` se concluir itens de fase mapeados.
- PRs de drivers PSC novos: incluir referência à documentação oficial do prestador e ambiente de homologação testado.

## Novos drivers PSC

Consulte [docs/PSC_PROVIDERS.md](docs/PSC_PROVIDERS.md) antes de implementar um adaptador.

Checklist mínimo:

- [ ] Implementa `PSCProvider`
- [ ] Builder com `ClientId`, `ClientSecret`, `Environment`
- [ ] Fluxo OAuth2 documentado
- [ ] Testes unitários com respostas mockadas
- [ ] Entrada na tabela de compatibilidade do README / documentação técnica

## Versionamento

Seguimos [Versionamento Semântico (SemVer)](docs/VERSIONING.md). Breaking changes só em major (`X.0.0`).

## Código de conduta

Este projeto adota o [Contributor Covenant](CODE_OF_CONDUCT.md). Participações devem respeitar esse código.

## Licença

Ao contribuir, você concorda que suas contribuições serão licenciadas sob a [Apache License 2.0](LICENSE).

## Dúvidas

Abra uma **issue** no GitHub com a tag `question` ou consulte a [documentação técnica](Documentacao_ICP_Brasil_Cloud_Signer_V12.md).
