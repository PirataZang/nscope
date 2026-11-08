# Decisões de projeto

Registro das escolhas feitas onde o prompt original deixava margem ou entrava em conflito. Mais simples e mais seguro vence.

1. **Sem commits automáticos.** O prompt pede um commit por marco, mas a regra global do usuário (`~/.claude/CLAUDE.md`) proíbe commitar sem pedido explícito. Valeu a regra do usuário: tudo fica no working tree.
2. **Dependências mínimas.** Fora: `clap` (4 flags se leem com `std::env`), `toml`/arquivo de configuração (opcional no prompt; nada a guardar ainda), `proptest` (uma varredura determinística de caracteres cobre a mesma propriedade), `crossterm` direto (o `ratatui` o reexporta), `anyhow`/`thiserror` (erros são `String` em português mostradas ao usuário).
3. **Privilégios sem `unsafe` nem libc.** `id -u` (Unix) e `net session` (Windows) via `Command`, sem shell. Em dúvida, responde "usuário comum". A opção Avançado → Modo de privilégios (`--privileged`) também vale para o nscope (nmap com capabilities).
4. **O runner recebe o programa como parâmetro** (`Runner::start(program, plan)`). Os testes usam um nmap falso por caminho absoluto: não é preciso mudar o `PATH` do processo (`set_var` é `unsafe` na edição 2024).
5. **Alvo inicial `scanme.nmap.org`** (como no protótipo): é o alvo de prática que o projeto Nmap permite e está na lista segura, então o primeiro `r` não exige confirmação.
6. **Layout em duas colunas desde 80 colunas.** Empilhar painéis só faria sentido abaixo de 80 colunas, onde a tela de "janela pequena" aparece. Larguras ≥ 80 usam lista (38–50 col.) + detalhes.
7. **Navegador de scripts NSE como linhas da lista** de Scripts (cabeçalhos pulados pelas setas), em vez de um painel com foco próprio: um só modelo de navegação.
8. **Campos auxiliares (`helper`)** como `zombie`, `plist`, `topn`: guardam valor, mas a flag é emitida pela escolha dona (`arg_from`). Só aparecem quando a escolha correspondente está ativa (`visible_if`).
9. **Flags extras recusam `-oN/-oX/-oG/-oS/-oA`, `--stats-every` e `--noninteractive`.** O nscope precisa saber onde está o XML e controla o progresso; esses campos existem na aba Saída.
10. **XML do nscope em temporário só se o usuário não definiu `-oX`/`-oA`.** Com `-oX -` (stdout) não há resultados a mostrar.
11. **Cancelar não junta as threads de leitura.** Se um processo neto segurasse o pipe, a interface travaria. As threads terminam sozinhas (EOF ou canal fechado). No término normal as threads são juntadas.
12. **Confirmação de autorização:** `s` apenas seleciona "Sim"; é preciso `Enter`. Padrão "Não". `-iL`/`-iR` sempre pedem confirmação (os alvos não são conhecidos).
13. **Alvos "seguros":** RFC 1918, loopback, link-local, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, `::1`, `fe80::/10`, `fc00::/7`, `2001:db8::/32`, `localhost`, `scanme.nmap.org` e domínios reservados (`.test`, `.localhost`, `.example`, `.invalid`, `.local`). Um CIDR/faixa só é seguro se inteiro dentro de um bloco.
14. **Ruído declarado dos perfis = ruído calculado**, garantido por teste (o protótipo divergia em alguns).
15. **`SIGTERM`/`SIGKILL` não são tratados** (sem crate de sinais, sem `unsafe`). `q` e `Ctrl+C` (que em modo raw chega como tecla) fazem a limpeza completa. Documentado em SECURITY.md.
16. **MSRV = 1.88** (exigência de `ratatui-widgets`). Para *rodar os testes* é preciso 1.89 (dependência de desenvolvimento do `insta`).
17. **GIF de demonstração:** `docs/demo.tape` (vhs) está pronto, mas o GIF não foi gerado neste ambiente; o README usa capturas de texto reais dos snapshots.
18. **Pipeline de release não executado localmente.** Os workflows usam SHAs reais de ações, mas só rodam no GitHub.
