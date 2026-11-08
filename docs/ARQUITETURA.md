# Arquitetura

## Separação lógica / UI / I/O

```
src/
├─ nmap/                  LÓGICA PURA (sem terminal, sem processos) — testes unitários
│  ├─ catalog.rs          opções como dados + `Values` (estado)           → docs/CATALOGO.md
│  ├─ validate.rs         alvos, portas, tempos, números, flags extras (lista de permitidos)
│  ├─ command.rs          Values → tokens (argv + exibição colorida + explicação), "em palavras simples"
│  ├─ analyze.rs          erros / avisos / info, escopo de alvos (autorização)
│  ├─ noise.rs            visibilidade estimada 0..5
│  ├─ profiles.rs         16 perfis (aplicam sobre Values)
│  ├─ knowledge.rs        portas conhecidas, estados, categorias/scripts NSE
│  ├─ xml.rs              XML do nmap → structs (sanitiza, tem limites)
│  └─ runner.rs           I/O: processo, threads, progresso, cancelamento, temporário 0700
├─ app.rs                 estado da UI + teclado/mouse (sem desenhar)
├─ ui/                    desenho (ratatui), uma tela por arquivo; só lê `App`
├─ report.rs              Markdown (create_new)
├─ util.rs                sanitização, quebra de linha, OSC 52, detecção de privilégios
└─ i18n.rs                textos da interface (pt-BR)
```

Regra de dependência: `nmap::*` (exceto `runner`) não importa nada de `app`/`ui`. `ui` só lê `App`. Só `runner` e `main` tocam processos/terminal.

## Fluxo de execução

1. `Values` (editado pela UI) → `command::build` → tokens. A barra de comando e a aba Comando usam os mesmos tokens.
2. `r` → `analyze` com os privilégios detectados. **Erro ⇒ não executa**, vai para a aba Comando.
3. `analyze::external_targets` ⇒ janela de confirmação (padrão Não).
4. `Plan::from_values` → `Runner::start`: `Command::new("nmap")` com argumentos em lista, `stdin` nulo; o nscope **antecipa** `--stats-every 1s` (se o usuário não definiu) e `-oX <tmp>/scan.xml` (se não definiu `-oX`/`-oA`).
5. Duas threads leem stdout/stderr (`read_until` com limite de 8 KiB, `from_utf8_lossy`, `util::clean`) e enviam por um canal limitado.
6. A cada tick (~100 ms) `App::tick` chama `Runner::poll`, que devolve as linhas novas e atualiza o progresso (`About 23.40% done ... (0:00:12 remaining)`).
7. Ao fim: esgota o canal, junta as threads, lê/parseia o XML (`xml::read_file`, ≤ 64 MiB), remove o temporário. `App` guarda o `ScanResult` e oferece os Resultados.
8. Cancelar (`c`), sair (`q`/`Ctrl+C`) ou `Drop` ⇒ `kill` + `wait` do filho e remoção do temporário.

## Como adicionar uma opção ao catálogo

Edite `build()` em `src/nmap/catalog.rs`, na seção certa (a ordem no arquivo é a ordem no comando):

```rust
n(Tempo, "minrate", "--min-rate", "Taxa mínima (pacotes/s)", "Texto simples do que faz.", 1, 10_000_000)
    .ph("1000").when("...").caution("..."),
```

Construtores: `b` (liga/desliga), `t` (texto), `n` (número com faixa), `tm` (tempo), `c` (escolha). Modificadores: `.fmt(Fmt::Cat|Eq)`, `.root(Root::Soft|Hard)`, `.val(Validator::...)`, `.show("outra_opcao","valor")`, `.standalone()`, `.helper()`.
Depois rode `UPDATE_CATALOG=1 cargo test catalogo` para regenerar `docs/CATALOGO.md`, e acrescente regras em `analyze.rs` se houver conflitos/avisos.
