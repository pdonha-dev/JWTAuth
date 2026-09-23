# JWTAuth

Aplicação educacional ASP.NET Core MVC que demonstra autenticação com JWT, senhas BCrypt, PostgreSQL e sessões de refresh token no Redis. O objetivo é tornar decisões e limites de segurança observáveis, não apresentar um servidor OAuth nem alegar prontidão para produção.

## Estado verificado em 2026-09-22

| Item | Estado |
|---|---|
| Build da solução | Validado localmente, sem warnings; SDK 10 compilando o alvo `net8.0` |
| Testes unitários | 7/7 aprovados via runtime roll-forward; cobertura de linhas do `JWTAuth.Core`: 21,9% (limite mínimo: 20%) |
| Formatação | Validada com `dotnet format --verify-no-changes` |
| Dependências vulneráveis | Nenhuma encontrada por `dotnet list package --vulnerable --include-transitive` |
| Sintaxe do Compose | Validada com placeholders locais por `docker compose config --quiet` |
| PostgreSQL/Redis/Testcontainers | 10 testes implementados; execução local tentada e bloqueada porque o daemon Docker estava indisponível |
| Fluxo Playwright | Implementado e compilado; pendente de execução local pela mesma limitação |
| Imagem/stack Docker | Implementada; pendente de execução local |

A CI executa os testes de infraestrutura de verdade e falha se Docker, PostgreSQL, Redis, a aplicação ou o navegador não iniciarem.

## Framework e dependências

O projeto permanece em **.NET 8 LTS**. A política oficial da Microsoft informa suporte até **10 de novembro de 2026**: <https://dotnet.microsoft.com/platform/support/policy/dotnet-core>. Na data desta revisão, 2026-09-22, o prazo restante é curto. A manutenção em .NET 8 reduz o risco desta correção e mantém compatibilidade com o projeto original, mas a migração para .NET 10 LTS é uma ação próxima, não uma evolução indefinidamente adiável.

Compatibilidade foi validada por restore e build, não por igualdade artificial de versões:

- ASP.NET Core/JWT Bearer 8.0.31;
- EF Core 8.0.11 e Npgsql EF Provider 8.0.11, alinhados porque o provider referencia EF Relational 8.0.11;
- System.IdentityModel.Tokens.Jwt 8.23.0;
- BCrypt.Net-Next 4.0.3;
- StackExchange.Redis 2.13.17;
- PostgreSQL 16.8 e Redis 7.4.2 nas imagens locais.

## Arquitetura

- `JWTAuth`: apresentação MVC, cookies, CSRF, autenticação e composição da aplicação.
- `JWTAuth.Core`: casos de uso de cadastro/login, hashing, emissão JWT e sessões Redis.
- `JWTAuth.Db`: `DbContext`, configuração relacional e migrations.
- `JWTAuth.Entities`: entidade persistida mínima.
- `JWTAuth.Tests.*`: testes unitários, integração real e navegador.

Warnings de compilação falham o build por meio de `Directory.Build.props`. Atualizações semanais de pacotes NuGet e GitHub Actions estão configuradas no Dependabot.

Não há Identity, AutoMapper, MediatR, CQRS ou repositório genérico. O serviço de autenticação usa EF Core diretamente porque as consultas e a constraint relacional são parte do caso de uso. Consulte [docs/architecture.md](docs/architecture.md).

## Modelo de autenticação

### Navegador MVC

O login cria uma sessão Redis e envia três cookies:

- `AccessToken`: JWT assinado, `HttpOnly`, `Secure`, `SameSite=Strict`, caminho `/`, duração padrão de 5 minutos;
- `RefreshToken`: valor opaco de 256 bits, `HttpOnly`, `Secure`, `SameSite=Strict`, caminho `/Auth`;
- `SessionCsrf`: segredo aleatório `HttpOnly`, `Secure`, `SameSite=Strict`, enviado também em campo oculto dos formulários de refresh/logout.

O valor utilizável do refresh token nunca é persistido. O Redis contém somente seu SHA-256, usuário, sessão, estado e expiração absoluta.

Cadastro e login usam o antiforgery nativo do ASP.NET Core. Refresh e logout usam double-submit vinculado à sessão. Essa proteção não depende da identidade do access token e continua válida depois que ele expira.

Novos nomes de usuário possuem entre 3 e 64 caracteres e aceitam somente letras ASCII, números, ponto, hífen e sublinhado. A validação existe na borda MVC e no serviço de aplicação; o índice normalizado continua sendo a garantia final de unicidade.

### Authorization versus cookie

O único esquema é JWT Bearer. Se `Authorization` estiver presente, ele sempre tem precedência. Um bearer inválido não faz fallback para o cookie. Sem header, o handler lê `AccessToken` do cookie para atender o MVC.

Esta aplicação não oferece uma API pública completa: os endpoints implementados são MVC e retornam views/redirecionamentos. A leitura de bearer permite demonstrar validação de JWT, mas não deve ser anunciada como contrato de API. Não há OpenAPI porque não há API pública.

### Refresh, concorrência e logout

`POST /Auth/Refresh` e `POST /Auth/Logout` são `AllowAnonymous`: autenticam a operação pelo refresh cookie e pelo token CSRF, portanto funcionam com access token expirado.

A rotação é um script Lua atômico em Redis standalone. Duas renovações do mesmo token têm um vencedor; a segunda é detectada como reuso e revoga a sessão, inclusive o sucessor. A mesma política se aplica quando o servidor rotaciona e a resposta se perde: repetir o token antigo encerra a sessão. É uma escolha conservadora contra replay, com o trade-off de poder desconectar abas concorrentes. A interface propõe renovação explícita para evitar múltiplos clientes renovando em paralelo.

Cada login cria uma sessão independente. Logout revoga somente a família apresentada. Cookies locais sempre são removidos, mas a interface diferencia revogação confirmada de falha/ausência no Redis.

A sessão expira absolutamente após 168 horas por padrão. Rotação não estende esse limite. Registros de tokens consumidos permanecem somente até esse prazo para detectar reuso sem crescimento ilimitado. Os scripts usam várias chaves e foram projetados para **Redis standalone**, não Redis Cluster.

Revogar refresh tokens não invalida imediatamente JWTs já emitidos. Um access token pode ser aceito até sua expiração curta.

## Pré-requisitos

- Docker Desktop com engine Linux ativo e Docker Compose v2;
- .NET SDK 8 para desenvolvimento local;
- PowerShell para o script de certificado;
- Git.

## Execução completa com Docker Compose

1. Clone o repositório correto:

   `git clone https://github.com/pdonha-dev/JWTAuth.git`

2. Copie `.env.example` para `.env` e substitua todos os placeholders. Gere uma chave JWT, por exemplo:

   `[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))`

3. Gere e confie o certificado HTTPS, usando a mesma senha definida em `HTTPS_CERT_PASSWORD`:

   `./scripts/setup-dev-certificate.ps1 -Password "sua-senha-local"`

   A chave privada fica em `.https/`, que é ignorado pelo Git e pelo contexto Docker, exceto pelo bind mount explícito do Compose.

4. Inicie sem apagar volumes existentes:

   `docker compose up --build --wait`

5. Abra **https://localhost:8443/Auth/Register**. `http://localhost:8080` existe apenas para redirecionar a HTTPS; cookies `Secure` são enviados e o login continua funcional no endereço HTTPS. O healthcheck só retorna sucesso quando PostgreSQL e Redis respondem.

6. Para encerrar:

   `docker compose down`

Não use `docker compose down -v` se quiser preservar os dados.

## Execução local sem container da aplicação

Mantenha PostgreSQL e Redis disponíveis e configure segredos no projeto web:

- `dotnet user-secrets --project JWTAuth set "ConnectionStrings:Database" "Host=localhost;Port=5432;Database=jwtauth;Username=...;Password=..."`
- `dotnet user-secrets --project JWTAuth set "ConnectionStrings:Redis" "localhost:6379,password=..."`
- `dotnet user-secrets --project JWTAuth set "Jwt:SigningKey" "uma-chave-aleatoria-com-32-bytes-ou-mais"`
- `dotnet run --project JWTAuth`

Não há segredo JWT padrão. Configuração ausente interrompe o startup com mensagem útil.

## Migrations

- Aplicar: `dotnet ef database update --project JWTAuth.Db --startup-project JWTAuth`
- Criar: `dotnet ef migrations add Nome --project JWTAuth.Db --startup-project JWTAuth`

`AddNormalizedUsername` preenche a coluna normalizada e procura colisões antes da constraint única. Se `Alice` e `alice` já existirem, a migration falha listando os identificadores conflitantes; nenhum usuário é removido ou renomeado automaticamente.

Credenciais anteriormente versionadas devem ser consideradas expostas e rotacionadas. O histórico Git não foi reescrito.

## Testes e qualidade

- Unitários: `dotnet test JWTAuth.Tests.Unit`
- Integração real (Docker obrigatório): `dotnet test JWTAuth.Tests.Integration`
- Formatação: `dotnet format JWTAuth.sln --verify-no-changes`
- Vulnerabilidades: `dotnet list JWTAuth.sln package --vulnerable --include-transitive`

Para o teste de navegador, inicie o Compose com `ACCESS_TOKEN_LIFETIME_SECONDS=5`, instale o Chromium e execute:

- `pwsh JWTAuth.Tests.Browser/bin/Debug/net8.0/playwright.ps1 install chromium`
- `$env:E2E_BASE_URL='https://localhost:8443'`
- `dotnet test JWTAuth.Tests.Browser`

O fluxo real é cadastro → login → perfil → expiração calculada pela claim `exp` → refresh → perfil → logout. O teste não ignora infraestrutura ausente: sem URL/stack ele falha.

A cobertura é um indicador de risco, não uma meta de 100%. A CI exige inicialmente 20% de linhas no Core e mantém persistência/Redis sob testes reais separados.

## Falhas e troubleshooting

- `DockerUnavailableException`: inicie o engine Linux do Docker Desktop.
- Login redireciona, mas perfil não autentica: confirme que está usando `https://localhost:8443` e que o certificado foi confiado.
- Startup informa configuração ausente: revise `.env` ou user-secrets; nomes usam `ConnectionStrings__Database`, `ConnectionStrings__Redis` e `Jwt__SigningKey` no ambiente.
- Migration falha por colisão: consulte os nomes informados, escolha manualmente como reconciliar as contas e execute novamente.
- Redis indisponível: login falha fechado; refresh retorna 503 e preserva os cookies; logout remove cookies, mas informa que a revogação não foi confirmada.
- Rate limiting: é em memória e por instância/IP. Em múltiplas instâncias, os limites não são globais.
- O ambiente local desta revisão tinha apenas o runtime .NET 10. Os testes unitários `net8.0` foram executados com `DOTNET_ROLL_FORWARD=Major`; use o runtime .NET 8 normalmente em uma estação compatível.

Mais cenários em [docs/security.md](docs/security.md).

## Limitações e próximos passos

- Migrar para .NET 10 LTS antes do fim do suporte do .NET 8.
- Redis Cluster não é suportado pelos scripts atuais.
- Não há revogação imediata de access tokens, MFA, recuperação de senha, e-mail ou login social.
- Não há configuração pronta de reverse proxy; se adicionada, restrinja proxies confiáveis antes de aceitar forwarded headers.
- A licença ainda não foi escolhida; nenhuma foi adicionada automaticamente.

## Roteiro e apresentação

O roteiro de cinco minutos está em [docs/demo.md](docs/demo.md).

Descrição curta sugerida para GitHub:

> Demonstração ASP.NET Core MVC de JWT em cookies seguros, refresh tokens opacos com rotação atômica no Redis e persistência PostgreSQL, coberta por testes unitários, Testcontainers e Playwright.

Tópicos sugeridos: `aspnet-core`, `jwt`, `postgresql`, `redis`, `bcrypt`, `testcontainers`, `playwright`, `docker-compose`, `authentication`.

## Uso de IA

Ferramentas de IA auxiliaram na inspeção, implementação, testes e documentação. O resultado foi revisado por build, análise de formatação e testes automatizados; verificações dependentes de Docker continuam explicitamente marcadas como pendentes, sem alegação de validação.
