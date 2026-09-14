Você é o engenheiro principal responsável por projetar, implementar, testar, documentar e preparar para produção o **SPECTER**, uma plataforma de Application Security / DevSecOps focada em encontrar problemas de segurança **antes e depois do deploy**.

Não trate esta tarefa como protótipo, exercício acadêmico, mockup ou landing page conceitual.

O objetivo é construir um produto funcional, instalável, testável, extensível e tecnicamente honesto.

---

# 1. PRODUTO

Nome:

SPECTER

Posicionamento:

Application security from source to production.

Conceito central:

O SPECTER acompanha a segurança de uma aplicação durante todo o ciclo:

SOURCE
↓
BUILD
↓
PREVIEW
↓
PRODUCTION
↓
MONITOR

O produto deve permitir:

1. analisar um projeto local;
2. analisar o build gerado;
3. analisar um preview deployment;
4. analisar um site já publicado;
5. comparar scans;
6. detectar regressões de segurança;
7. impedir deploys quando regras críticas forem violadas;
8. gerar relatórios adequados para humanos e ferramentas;
9. integrar com CI/CD;
10. futuramente operar como plataforma contínua de monitoramento.

---

# 2. PRINCÍPIO DE SEGURANÇA

O SPECTER é uma ferramenta defensiva.

Não implementar funcionalidades destinadas a:

- exploração de vulnerabilidades;
- execução de exploits;
- brute force;
- credential stuffing;
- bypass de autenticação;
- evasão de WAF;
- payloads destrutivos;
- persistência;
- movimentação lateral;
- exfiltração;
- execução remota;
- exploração automatizada de CVEs;
- ataques contra terceiros.

Scans remotos padrão devem ser:

- passivos;
- não destrutivos;
- de baixo impacto;
- baseados em comportamento observável externamente.

Qualquer funcionalidade futura que envolva testes mais invasivos deve exigir comprovação explícita de propriedade/autorização do domínio.

Nunca realizar testes destrutivos automaticamente.

---

# 3. EXPERIÊNCIA PRINCIPAL

O usuário deve poder rodar:

```bash
npx @specter/cli scan

```

para analisar o projeto atual.

Também:

```bash
npx @specter/cli scan https://example.com

```

para analisar uma aplicação publicada.

Outros comandos previstos:

```bash
specter scan
specter scan <url>
specter scan --json
specter scan --sarif
specter scan --ci
specter scan --fail-on high
specter scan --output ./report
specter compare <scan-a> <scan-b>
specter doctor
specter init
specter config
specter version

```

A CLI deve funcionar de verdade.

Nada de comandos falsos ou respostas mockadas.

---

# 4. ARQUITETURA

Use monorepo.

Estrutura alvo:

```text
specter/
├─ apps/
│  ├─ dashboard/
│  └─ api/
│
├─ packages/
│  ├─ cli/
│  ├─ core/
│  ├─ scanner-static/
│  ├─ scanner-build/
│  ├─ scanner-web/
│  ├─ scanner-dependencies/
│  ├─ scanner-secrets/
│  ├─ risk-engine/
│  ├─ reporter/
│  ├─ config/
│  ├─ types/
│  └─ ui/
│
├─ integrations/
│  └─ github-action/
│
├─ examples/
│  ├─ vulnerable-react/
│  ├─ secure-react/
│  ├─ vulnerable-next/
│  └─ secure-next/
│
├─ docs/
├─ tests/
└─ scripts/

```

Use:

- TypeScript;
- Node.js;
- pnpm workspaces;
- Turborepo;
- Next.js para dashboard;
- React;
- Tailwind CSS;
- PostgreSQL;
- Prisma;
- Playwright;
- Vitest;
- ESLint;
- Prettier.

Backend:

- Node.js;
- Fastify ou camada server equivalente bem estruturada.

Jobs futuros:

- Redis;
- BullMQ.

Não adicionar Redis se ainda não houver necessidade concreta no MVP.

---

# 5. CORE DOMAIN

Defina tipos compartilhados.

Exemplo conceitual:

```ts
type Severity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

type FindingCategory =
  | "secret"
  | "dependency"
  | "source"
  | "configuration"
  | "headers"
  | "cookies"
  | "cors"
  | "csp"
  | "tls"
  | "client-exposure"
  | "third-party"
  | "route"
  | "runtime"
  | "build";

interface Finding {
  id: string;
  ruleId: string;

  title: string;
  description: string;

  severity: Severity;
  category: FindingCategory;

  file?: string;
  line?: number;
  column?: number;

  url?: string;

  evidence?: unknown;

  remediation?: string;

  confidence: "low" | "medium" | "high";

  source:
    | "static"
    | "build"
    | "dependency"
    | "remote";

  fingerprint: string;
}

```

Também criar:

- Scan;
- ScanTarget;
- ScanResult;
- Rule;
- RuleMetadata;
- RiskScore;
- ScanDiff;
- SecurityRegression;
- ExternalDomain;
- RouteInfo.

Todos os formatos devem ser versionados.

---

# 6. SCAN LOCAL — SOURCE

O scanner de código deve analisar arquivos JS/TS:

- `.js`;
- `.jsx`;
- `.ts`;
- `.tsx`;
- `.mjs`;
- `.cjs`.

Preferir AST em vez de regex quando análise semântica for necessária.

Pode usar:

- TypeScript compiler API;
- Babel parser;
- SWC parser;

desde que a arquitetura seja consistente.

Detectar inicialmente:

## Secrets

Possíveis:

- API keys;
- tokens;
- JWTs;
- private keys;
- database URLs;
- AWS-style credentials;
- Stripe secret keys;
- GitHub tokens;
- OAuth secrets.

Evitar falsos positivos em:

- `.env.example`;
- fixtures;
- documentação;
- placeholders;
- testes conhecidos.

Nunca imprimir o secret inteiro.

Exemplo:

```text
sk_live_abc***********

```

ou simplesmente:

```text
[REDACTED]

```

---

# 7. CLIENT EXPOSURE

Verificar possíveis valores privados chegando ao browser.

Especial atenção:

Next.js:

- `NEXT_PUBLIC_*`;
- imports server/client;
- client components.

Vite:

- `VITE_*`;
- `import.meta.env`.

Detectar referências suspeitas como:

- DATABASE\_URL;
- PRIVATE\_KEY;
- SECRET\_KEY;
- STRIPE\_SECRET\_KEY;
- INTERNAL\_API\_TOKEN.

Também analisar o build final para identificar o que realmente está presente nos bundles.

Esse ponto é obrigatório:

Não confiar apenas no código-fonte.

Verificar o artefato gerado.

---

# 8. DANGEROUS CODE PATTERNS

Criar regras iniciais para:

- `eval`;
- `new Function`;
- uso inseguro de `dangerouslySetInnerHTML`;
- `document.write`;
- URLs HTTP;
- armazenamento de tokens sensíveis em localStorage;
- configuração de CORS excessivamente permissiva;
- uso potencialmente inseguro de cookies;
- debug ativo em produção;
- stack traces expostos;
- valores sensíveis em `console.log`.

Não assumir que todo uso é vulnerabilidade.

Aplicar:

- severity;
- confidence;
- contexto;
- evidência.

---

# 9. DEPENDENCY SCANNER

Analisar:

- package.json;
- lockfile.

Suportar inicialmente:

- pnpm;
- npm;
- yarn.

Produzir:

- total de dependências;
- vulnerabilidades conhecidas;
- severidade;
- pacote afetado;
- versão instalada;
- versão corrigida quando conhecida.

Não depender exclusivamente da saída textual de `npm audit`.

Criar uma interface desacoplada para providers de vulnerabilidade.

Formato:

```text
DependencyFinding
package
installedVersion
patchedVersion
advisory
severity
directDependency

```

Sempre informar quando uma vulnerabilidade pertence apenas a dependência transitiva.

---

# 10. BUILD SCANNER

Detectar automaticamente:

- Next.js;
- Vite;
- React;
- outros projetos JS compatíveis.

Quando possível:

1. executar build;
2. localizar output;
3. analisar artefatos.

Nunca executar script arbitrário desconhecido sem controle.

Modo seguro por padrão.

Analisar:

- JavaScript bundles;
- source maps;
- arquivos `.env` copiados;
- secrets;
- endpoints internos;
- URLs privadas;
- chaves;
- debug information;
- arquivos desnecessários;
- source maps públicos;
- stack traces.

---

# 11. REMOTE SCAN

Comando:

```bash
specter scan https://example.com

```

O scanner remoto deve inicialmente ser não destrutivo.

Verificar:

## HTTPS / TLS

- HTTPS disponível;
- redirect HTTP → HTTPS;
- certificado válido;
- hostname;
- expiração;
- protocolos inseguros quando detectáveis.

## Headers

Verificar:

- Content-Security-Policy;
- Strict-Transport-Security;
- X-Content-Type-Options;
- Referrer-Policy;
- Permissions-Policy;
- frame protections;
- Cache-Control em conteúdo sensível quando observável.

Evitar simplesmente marcar ausência como CRITICAL.

Usar contexto.

---

# 12. COOKIES

Inspecionar cookies recebidos.

Verificar:

- Secure;
- HttpOnly;
- SameSite;
- domínio;
- path;
- lifetime.

Diferenciar:

- cookie de sessão;
- analytics;
- preferências;
- cookies desconhecidos.

Nunca mostrar conteúdo sensível integral do cookie.

---

# 13. CSP

Interpretar Content-Security-Policy.

Detectar:

- ausência;
- `unsafe-inline`;
- `unsafe-eval`;
- wildcard excessivo;
- fontes extremamente permissivas;
- ausência de `object-src`;
- frame ancestors quando relevante.

Mostrar recomendações contextualizadas.

Nunca afirmar que uma CSP é "segura" apenas porque existe.

---

# 14. CORS

Inspecionar respostas observáveis.

Detectar configurações claramente permissivas.

Não tentar explorar CORS.

Reportar apenas o que puder ser observado com segurança.

---

# 15. THIRD-PARTY MAP

Identificar recursos externos carregados.

Construir:

```text
YOUR APP
├─ api.example.com
├─ fonts.gstatic.com
├─ stripe.com
├─ analytics.example
└─ new-domain.example

```

Guardar:

- domínio;
- tipo do recurso;
- primeira ocorrência;
- página;
- script relacionado quando possível.

Classificação:

- first-party;
- known third-party;
- unknown;
- newly introduced.

---

# 16. ROUTE DISCOVERY

Descobrir rotas acessíveis através de:

- links HTML;
- sitemap;
- navegação Playwright;
- rotas observadas.

Não fazer brute-force de diretórios.

Não tentar descobrir endpoints por wordlists agressivas.

Representação:

```text
/
├─ /login
├─ /register
├─ /dashboard
└─ /settings

```

Para endpoints observados:

```text
/api/auth
/api/users
/api/projects

```

Guardar:

- método;
- status;
- content type;
- authentication observable;
- CORS;
- headers.

---

# 17. PLAYWRIGHT

Usar Playwright para runtime scan.

Durante navegação capturar:

- requests;
- responses;
- console errors;
- page errors;
- redirects;
- mixed content;
- external domains;
- cookies;
- headers;
- CSP violations observáveis.

Manter navegação segura.

Não enviar formulários que possam:

- criar dados;
- excluir dados;
- efetuar compras;
- alterar contas;
- provocar ações irreversíveis.

---

# 18. SECURITY SCORE

Criar Risk Engine separado.

Score:

```text
0–100

```

Não fazer média ingênua.

Peso maior:

critical > high > medium > low.

Também considerar:

- confiança;
- contexto;
- finding novo vs existente;
- área afetada.

Exemplo:

```text
Security Score

94 / 100

Critical     0
High         0
Medium       2
Low          4

```

Evitar falsa precisão.

Documentar exatamente como o score é calculado.

---

# 19. BASELINES

Permitir:

```bash
specter scan --baseline .specter/baseline.json

```

Objetivo:

não falhar CI por findings antigos já conhecidos.

O gate deve poder falhar apenas quando:

- surge finding novo;
- severidade aumenta;
- configuração piora;
- score cai além do limite.

---

# 20. SECURITY REGRESSION

Implementar comparação:

```bash
specter compare previous.json current.json

```

Resultado:

```text
SECURITY REGRESSION

Score
94 → 81

New findings
+ 1 HIGH
+ 2 MEDIUM

Resolved
- 3 LOW

```

Identificar findings através de fingerprints estáveis.

Mostrar:

- new;
- unchanged;
- resolved;
- severity changed.

---

# 21. CI MODE

Suportar:

```bash
specter scan --ci

```

Flags:

```bash
--fail-on critical
--fail-on high
--max-score-drop 5
--baseline <path>

```

Exit codes documentados.

Exemplo:

```text
0 = success
1 = security gate failed
2 = configuration error
3 = scan failure

```

---

# 22. SARIF

Gerar SARIF 2.1.0 válido.

```bash
specter scan --sarif > specter.sarif

```

Compatível com GitHub Code Scanning quando possível.

Mapear corretamente:

- ruleId;
- severity;
- file;
- line;
- message;
- remediation.

Validar schema.

---

# 23. JSON

Criar schema versionado.

Exemplo:

```json
{
  "schemaVersion": "1",
  "scanId": "...",
  "target": {},
  "score": 91,
  "summary": {},
  "findings": []
}

```

Nunca mudar silenciosamente formato público.

---

# 24. CONFIGURAÇÃO

Arquivo:

```text
specter.config.ts

```

Exemplo:

```ts
export default {
  failOn: "high",

  ignore: [
    "SPECTER-LOW-001"
  ],

  scan: {
    source: true,
    build: true,
    dependencies: true,
    remote: true
  }
};

```

Validar config estritamente.

Erros desconhecidos devem falhar com mensagem clara.

---

# 25. IGNORE / SUPPRESSION

Permitir suppression apenas explicitamente.

Exemplo:

```text
.specterignore

```

ou config.

Toda suppression deve permitir:

- motivo;
- validade opcional;
- ruleId;
- fingerprint.

Evitar:

```text
ignoreEverything: true

```

Registrar suppressions no relatório.

---

# 26. CLI UX

A CLI deve parecer produto profissional.

Exemplo:

```text
SPECTER
Application security from source to production.

Target
https://example.com

Scanning

✓ TLS
✓ Security headers
✓ Cookies
✓ Third-party resources
✓ Runtime
✓ Routes

Security Score
91/100

CRITICAL     0
HIGH         0
MEDIUM       3
LOW          7

3 findings require attention.

Run:

specter scan --json

for machine-readable output.

```

Não exagerar em animações de terminal.

Não usar frases genéricas de IA.

---

# 27. DASHBOARD

Criar dashboard funcional depois que o core estiver pronto.

Nunca priorizar dashboard antes da engine.

Visual:

- dark;
- sofisticado;
- técnico;
- minimalista;
- denso na medida certa;
- aparência de ferramenta profissional.

Evitar:

- gradientes roxos genéricos;
- glassmorphism excessivo;
- 4 cards gigantes em cima;
- emojis;
- “Welcome back”;
- copy genérica de SaaS;
- layout com cara de template de IA.

Referência conceitual:

debugger + terminal + observability + security console.

---

# 28. DASHBOARD — HOME

Mostrar:

```text
SPECTER

example.com

PRODUCTION                     91

Code Security                  98
Dependencies                   94
Client Exposure               100
Runtime Configuration          86
Attack Surface                 82

Last scan
2 minutes ago

Regression
94 → 91

NEW FINDINGS

MEDIUM  CSP weakened
MEDIUM  New third-party script
LOW     Missing Permissions-Policy

```

---

# 29. FINDING VIEW

Cada finding deve mostrar:

- título;
- severity;
- confidence;
- categoria;
- origem;
- evidência;
- arquivo ou URL;
- linha;
- primeira detecção;
- última detecção;
- remediation;
- documentação;
- fingerprint;
- status;
- suppression.

---

# 30. HISTORY

Criar timeline:

```text
SEP 01   94
SEP 04   94
SEP 08   87
SEP 12   71

```

Permitir selecionar dois scans.

Mostrar diff.

---

# 31. ATTACK SURFACE VIEW

Criar visualização:

```text
example.com

/
├─ login
├─ register
├─ dashboard
└─ settings

API
├─ /api/auth
├─ /api/users
└─ /api/projects

```

Isso é visualização defensiva de superfície observada.

Não implementar exploração.

---

# 32. DOMAIN TRUST VIEW

Criar grafo/visualização de conexões externas.

Mostrar:

- first-party;
- third-party;
- new;
- removed.

O foco é visualizar supply-chain de browser.

---

# 33. AUTHENTICATION

Dashboard SaaS pode usar:

- GitHub OAuth inicialmente.

Criar:

- users;
- organizations;
- projects;
- domains;
- scans;
- findings.

RBAC básico:

- owner;
- admin;
- member;
- viewer.

Não complicar RBAC na primeira versão.

---

# 34. DATABASE

PostgreSQL + Prisma.

Entidades mínimas:

User

Organization

OrganizationMember

Project

Domain

DomainVerification

Scan

Finding

FindingOccurrence

Suppression

ExternalDomain

Route

Deployment

Integration

ApiKey

---

# 35. MULTI-TENANCY

Todos os dados precisam estar associados corretamente a:

organization → project.

Nunca confiar apenas em IDs enviados pelo client.

Toda query deve validar ownership/autorização.

---

# 36. DOMAIN OWNERSHIP

Para scans remotos comuns:

permitir apenas verificações passivas.

Para funcionalidades futuras avançadas:

exigir verificação.

Métodos:

DNS TXT:

```text
specter-verification=<token>

```

ou:

```text
/.well-known/specter-verification.txt

```

Token deve:

- ser aleatório;
- ter expiração quando necessário;
- não ser previsível.

---

# 37. API KEYS

Criar chaves para CI.

Formato conceitual:

```text
sp_live_xxxxxxxxx

```

No banco:

armazenar hash.

Nunca armazenar chave completa após criação.

Mostrar apenas uma vez.

---

# 38. API

API versionada:

```text
/api/v1/

```

Rotas mínimas:

```text
POST /projects
GET  /projects
GET  /projects/:id

POST /scans
GET  /scans/:id
GET  /projects/:id/scans

GET /findings/:id

POST /suppressions

POST /domains/:id/verify

```

Input validation obrigatória.

Use schema validation.

---

# 39. RATE LIMIT

Adicionar rate limiting em endpoints sensíveis.

Principalmente:

- login;
- API keys;
- scans;
- verification.

---

# 40. LOGGING

Logs estruturados.

Nunca logar:

- passwords;
- tokens;
- cookies;
- authorization headers;
- secrets;
- raw form fields sensíveis.

Adicionar request ID.

---

# 41. PRIVACIDADE

O scanner deve minimizar coleta.

Por padrão:

não armazenar:

- passwords;
- session tokens;
- cookie contents;
- form contents;
- personal data encontrada em páginas.

Usar sanitização.

---

# 42. REDACTION

Criar módulo central de redaction.

Qualquer finding/evidence deve passar por ele antes de:

- terminal;
- JSON;
- banco;
- logs;
- dashboard.

Testar redaction extensivamente.

---

# 43. GITHUB ACTION

Criar integração oficial.

Exemplo:

```yaml
- uses: specter-security/action@v1
  with:
    fail-on: high

```

Resultado esperado em PR:

```text
SPECTER SECURITY

Score: 91

✓ Secrets
✓ Dependencies
✓ Client exposure
⚠ Runtime configuration

New findings
0 Critical
0 High
2 Medium

```

---

# 44. PR COMMENT

Futuramente permitir comentário automatizado na PR.

Não duplicar comentários.

Atualizar comentário existente.

---

# 45. DEPLOY GATE

O SPECTER deve conseguir falhar pipeline quando:

- há Critical novo;
- há High novo conforme config;
- score cai mais que limite;
- regra obrigatória falha.

Nunca bloquear deploy apenas por warning antigo quando baseline estiver configurado.

---

# 46. TESTES

Não considerar feature pronta sem testes.

Criar:

Unit tests:

- parsers;
- scanners;
- rules;
- risk engine;
- redaction;
- fingerprints;
- config;
- formatter.

Integration tests:

- scan local;
- build scan;
- remote scan.

E2E:

- CLI;
- dashboard quando existir.

Criar aplicações propositalmente inseguras dentro de `examples/`.

Nunca depender de sistemas externos frágeis durante a suite padrão.

---

# 47. FIXTURES

Criar fixtures para:

- exposed secret;
- unsafe eval;
- insecure cookie;
- missing CSP;
- source map;
- third-party script;
- client env exposure;
- vulnerable dependency;
- safe versions equivalentes.

Testar positivos e negativos.

---

# 48. FALSOS POSITIVOS

Este é um requisito importante.

Cada regra deve ter:

- documentação;
- exemplos inseguros;
- exemplos seguros;
- severidade;
- confiança;
- possíveis falsos positivos.

Não aumentar número de findings artificialmente.

Qualidade > quantidade.

---

# 49. PERFORMANCE

O scanner não deve carregar arquivos gigantes indiscriminadamente.

Implementar:

- ignore `node_modules`;
- ignore `.git`;
- ignore caches;
- ignore binaries;
- tamanho máximo configurável;
- concorrência limitada.

Evitar consumir memória sem controle.

---

# 50. CANCELAMENTO

CLI deve reagir corretamente a SIGINT.

Fechar:

- browser;
- workers;
- streams;
- temporários.

Não deixar processos órfãos.

---

# 51. TEMP FILES

Arquivos temporários devem:

- usar diretório seguro;
- ser removidos;
- não conter secrets desnecessariamente.

---

# 52. ERROR HANDLING

Não usar:

```ts
catch {}

```

sem motivo explícito.

Erros devem ter tipos claros.

CLI precisa diferenciar:

- erro de configuração;
- erro de rede;
- erro interno;
- gate failure.

---

# 53. DOCUMENTAÇÃO

Criar:

README.md

docs/getting-started.md

docs/cli.md

docs/configuration.md

docs/rules.md

docs/security-model.md

docs/privacy.md

docs/architecture.md

docs/ci.md

docs/remote-scanning.md

docs/false-positives.md

docs/contributing.md

---

# 54. README

README não deve vender funcionalidades inexistentes.

Estrutura:

- o que é;
- por quê;
- quick start;
- exemplo;
- capacidades reais;
- CI;
- output;
- config;
- arquitetura resumida;
- roadmap;
- security model;
- limitations.

Nunca escrever:

“AI-powered security”

se não existir uma função concreta de IA.

---

# 55. SECURITY MODEL

Documentar claramente:

O SPECTER:

- encontra sinais e configurações inseguras;
- reduz riscos comuns;
- não prova ausência de vulnerabilidades;
- não substitui auditoria profissional;
- não é ferramenta de exploração.

---

# 56. VERSIONAMENTO

SemVer.

Começar:

```text
0.1.0

```

Não chamar de `1.0.0` enquanto:

- API;
- schema;
- config;
- rules;

ainda estiverem mudando rapidamente.

---

# 57. RELEASE 0.1.0

Obrigatório:

- CLI;
- source scan;
- secret detection;
- dangerous patterns;
- dependency scan;
- remote headers;
- cookies;
- TLS básico;
- CSP;
- third-party discovery;
- JSON;
- SARIF;
- score;
- config;
- CI exit codes;
- testes;
- docs.

Não fazer dashboard antes desses itens estarem sólidos.

---

# 58. RELEASE 0.2.0

Adicionar:

- build scanner;
- bundle exposure;
- source maps;
- Playwright runtime scan;
- route discovery;
- external domain map;
- regression diff.

---

# 59. RELEASE 0.3.0

Adicionar:

- GitHub Action;
- baselines;
- deploy gate;
- PR reports;
- regression policies.

---

# 60. RELEASE 0.4.0

Adicionar dashboard:

- auth;
- projects;
- scans;
- findings;
- history;
- diff;
- attack surface;
- domains.

---

# 61. RELEASE 0.5.0

Adicionar monitoramento periódico:

- scheduled scans;
- regressions;
- notifications;
- domain changes;
- third-party changes.

---

# 62. FUTURO — NÃO IMPLEMENTAR PREMATURAMENTE

Somente depois do core estabilizar:

- Slack;
- email alerts;
- Vercel integration;
- GitLab;
- Bitbucket;
- Jira;
- Linear;
- SBOM;
- SLSA/provenance;
- organization policies;
- custom rules;
- plugins;
- API pública completa.

---

# 63. NÃO IMPLEMENTAR IA SÓ POR MARKETING

Não adicionar chatbot ou “AI security assistant” simplesmente para dizer que existe IA.

Se futuramente houver análise assistida por modelo:

- findings continuam determinísticos;
- IA pode explicar;
- IA não decide sozinha severidade;
- IA não cria evidência inexistente;
- IA não executa ações ofensivas.

---

# 64. DESIGN

O design deve ter identidade própria.

SPECTER deve parecer:

- técnico;
- silencioso;
- preciso;
- sofisticado;
- quase forense.

Paleta preferencial:

- preto;
- grafite;
- branco;
- cinza.

Cores de severidade apenas onde necessário.

Typography:

- sans moderna;
- mono para dados técnicos.

Evitar excesso de rounded cards.

Usar:

- tabelas;
- linhas;
- grids;
- timeline;
- hierarquia tipográfica;
- espaços bem controlados.

---

# 65. LANDING PAGE

Só criar quando produto funcional existir.

Headline sugerida:

```text
Break your app before someone else does.

```

Subheadline:

```text
SPECTER finds security regressions from source code to production before they become incidents.

```

Não lotar a landing com buzzwords.

---

# 66. QUALIDADE DO CÓDIGO

Exigir:

- TypeScript strict;
- sem `any` desnecessário;
- módulos pequenos;
- dependências justificadas;
- responsabilidades claras;
- APIs internas estáveis;
- naming consistente.

Não criar abstrações prematuras.

---

# 67. GIT

Antes de alterar:

```bash
git status
git branch --show-current
git log --oneline -10

```

Preservar alterações existentes.

Nunca usar:

```bash
git reset --hard
git clean -fd

```

sem autorização explícita.

Commits pequenos e coerentes.

Não misturar dezenas de assuntos.

---

# 68. EXECUÇÃO

Não responda apenas com plano.

Implemente.

Quando encontrar problema:

1. investigar;
2. corrigir;
3. testar;
4. continuar.

Não deixar TODO como substituição para requisito obrigatório.

---

# 69. NÃO INVENTAR SUCESSO

Nunca afirmar:

- build passou;
- teste passou;
- scan funcionou;
- package publicou;
- deploy funcionou;

sem executar e verificar.

---

# 70. COMANDOS DE VALIDAÇÃO

Antes de considerar release pronta:

```bash
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build

```

Executar também E2E relevante.

---

# 71. PACKAGE

CLI deve ser publicável via npm.

Nome sugerido:

```text
@specter-security/cli

```

Se indisponível, escolher namespace coerente.

Binário:

```text
specter

```

---

# 72. PACKAGE CONTENTS

Garantir que npm package não inclua:

- testes desnecessários;
- secrets;
- cache;
- source maps privados;
- arquivos gigantes;
- documentação interna irrelevante.

Validar com:

```bash
npm pack --dry-run

```

---

# 73. SUPPLY CHAIN

CI:

- lockfile obrigatório;
- dependabot/Renovate opcional;
- permissions mínimas no GitHub Actions;
- actions preferencialmente pinned;
- evitar execução insegura de PR forks.

---

# 74. SECURITY DO PRÓPRIO SPECTER

Trate o SPECTER como software de segurança.

Portanto:

- sanitizar inputs;
- validar URLs;
- proteger contra SSRF;
- bloquear endereços privados em scans cloud quando necessário;
- limitar redirects;
- limitar response size;
- timeouts;
- controlar DNS rebinding;
- não permitir `file://`;
- não acessar metadata services.

Este item é obrigatório.

---

# 75. SSRF

Remote scanner deve validar targets.

Em serviço cloud bloquear:

- localhost;
- 127.0.0.0/8;
- \::1;
- redes privadas RFC1918;
- link-local;
- metadata endpoints;
- esquemas que não sejam HTTP/HTTPS.

Revalidar destino após DNS resolution e redirects.

---

# 76. LIMITES

Configurar:

- timeout por request;
- total scan timeout;
- max redirects;
- max pages;
- max response bytes;
- concurrency.

Valores padrão conservadores.

---

# 77. DATABASE SAFETY

Prisma migrations versionadas.

Nunca usar:

```bash
prisma db push

```

em produção como mecanismo principal.

Usar migrations.

---

# 78. OBSERVABILITY

Adicionar:

- structured logs;
- request IDs;
- duração de scans;
- número de findings;
- erros internos.

Sem armazenar dados sensíveis.

---

# 79. DEFINITION OF DONE — REGRA

Uma feature só está pronta quando:

- código existe;
- integração existe;
- testes passam;
- edge cases principais foram cobertos;
- documentação está atualizada;
- output é honesto.

---

# 80. MVP COMPLETO

Primeiro objetivo concreto:

Fazer isto funcionar:

```bash
git clone <repo>
cd example-project

npx @specter-security/cli scan

```

e produzir:

```text
SPECTER

Project
example-project

SOURCE
✓ 187 files scanned

SECRETS
✓ No exposed secrets

CODE SECURITY
⚠ 2 findings

DEPENDENCIES
⚠ 1 vulnerable dependency

Security Score
88/100

HIGH       0
MEDIUM     2
LOW        1

Report saved:
.specter/report.json

```

E:

```bash
npx @specter-security/cli scan https://example.com

```

produzir:

```text
SPECTER LIVE

https://example.com

TLS                    PASS
Security Headers       WARN
CSP                    WARN
Cookies                PASS
External Domains       6
Routes                  12

Security Score
84/100

```

---

# 81. PRODUTO FINAL

A visão final é:

```text
                    SPECTER
                       │
        ┌──────────────┼───────────────┐
        │              │               │
      SOURCE          BUILD         PRODUCTION
        │              │               │
   Static Scan     Bundle Scan      Live Scan
   Secrets         Exposure         Headers
   Config          Source Maps      Cookies
   Dependencies    Assets           CSP
        │              │            Routes
        └──────────────┼───────────────┘
                       │
                  Risk Engine
                       │
                Security History
                       │
                Regression Engine
                       │
                  Deploy Gate
                       │
                  Dashboard

```

---

# 82. DIFERENCIAL DO PRODUTO

O SPECTER não deve competir apenas por:

“quantas vulnerabilidades encontra”.

O principal diferencial deve ser:

**Security Regression Detection.**

Ou seja:

```text
Ontem:

94/100

Hoje:

81/100

```

SPECTER deve explicar:

```text
Why?

+ CSP weakened
+ Source maps exposed
+ New external script
+ Cookie lost SameSite

```

Essa deve ser a identidade técnica central do produto.

---

# 83. FILOSOFIA

O produto deve responder quatro perguntas:

1. O que está inseguro?
2. Onde está?
3. Quando apareceu?
4. O que mudou para isso acontecer?

Se uma feature não ajuda a responder nenhuma dessas perguntas, questione se ela realmente pertence ao produto.

---

# 84. ORDEM DE IMPLEMENTAÇÃO

Execute estritamente nesta ordem:

PHASE 1
Monorepo + tooling + types.

PHASE 2
Core rule engine.

PHASE 3
Source scanner.

PHASE 4
Secret detection + redaction.

PHASE 5
Dependency scanner.

PHASE 6
CLI.

PHASE 7
JSON + SARIF.

PHASE 8
Risk engine.

PHASE 9
Remote scanner.

PHASE 10
Headers + TLS + cookies + CSP.

PHASE 11
Build scanner.

PHASE 12
Playwright runtime scanner.

PHASE 13
Route + third-party discovery.

PHASE 14
Scan diff/regression.

PHASE 15
Baseline + CI gate.

PHASE 16
GitHub Action.

PHASE 17
Persistence/API.

PHASE 18
Dashboard.

PHASE 19
History + attack surface.

PHASE 20
Release hardening.

Não avance para UI bonita enquanto a engine principal estiver incompleta.

---

# 85. AO FINAL DE CADA PHASE

Execute:

- lint;
- typecheck;
- testes relevantes;
- build relevante.

Informe objetivamente:

- implementado;
- testes;
- falhas;
- decisões técnicas;
- próximo passo.

Continue trabalhando.

Não pare apenas para pedir confirmação se o próximo passo já estiver definido nesta especificação.

---

# 86. RELEASE HARDENING FINAL

Antes de declarar o projeto pronto:

Faça uma revisão completa procurando:

- mocks esquecidos;
- TODOs;
- `console.log`;
- `any`;
- dead code;
- secrets;
- dependências não utilizadas;
- endpoints sem auth;
- inconsistências de tipos;
- race conditions;
- erros silenciosos;
- timeout ausente;
- SSRF;
- path traversal;
- command injection;
- unsafe child processes;
- logs sensíveis;
- falta de redaction;
- documentação desatualizada.

Corrigir os problemas encontrados.

---

# 87. TESTE REAL FINAL

Criar três cenários.

## Projeto seguro

Resultado esperado:

score alto e nenhum finding grave.

## Projeto propositalmente inseguro

Deve encontrar:

- secret;
- dangerous code;
- client exposure;
- dependency issue.

## Site local vulnerável

Deve encontrar:

- missing headers;
- cookie flags;
- weak CSP;
- third-party domain.

Os resultados precisam ser determinísticos.

---

# 88. CRITÉRIO DE PORTFÓLIO

Ao final o repositório deve permitir que um recrutador faça:

```bash
git clone ...
pnpm install
pnpm build
pnpm test
pnpm specter scan examples/vulnerable-next

```

e veja o produto funcionando.

Não dependa de screenshots para provar funcionalidade.

---

# 89. NÃO OTIMIZE PARA QUANTIDADE

Prefiro:

20 regras boas

a:

300 regras superficiais.

Prefiro:

5 módulos realmente funcionais

a:

30 comandos falsos.

Prefiro:

uma arquitetura limpa

a:

uma arquitetura enorme impossível de manter.

---

# 90. RESULTADO ESPERADO

Quando tudo estiver concluído, o SPECTER deve poder ser apresentado como:

**SPECTER is an application security platform that analyzes source code, build artifacts and production environments, tracks security regressions between releases and integrates security gates directly into CI/CD.**

O produto deve ser executável, demonstrável e tecnicamente defensável.

Não entregue somente documentação.

Não entregue somente UI.

Não entregue somente arquitetura.

Construa o produto.

Comece agora pela inspeção do repositório e pela Phase 1.

Continue sequencialmente até que todas as fases tecnicamente possíveis estejam implementadas, testadas e documentadas.