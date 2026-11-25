# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/); versionamento semântico.

## [Não lançado]

### Adicionado
- Histórico de execuções: cada scan da sessão fica guardado e aparece na lista *Execuções* em Resultados. `s` salva tudo numa pasta `nscope-historico-<data>/` (índice, relatório, XML e saída de cada execução) na pasta onde o terminal foi aberto.
- Aba **Editar** (5): o comando inteiro num bloco editável; o texto é lido a cada tecla, vira as opções das outras abas e cada parte é explicada embaixo. Flags desconhecidas vão para o campo de flags extras. `Esc` desfaz.

### Mudado
- No Linux/macOS o nscope abre com sudo por padrão (`--sem-sudo` pula). Arquivos salvos continuam com o usuário que chamou o sudo como dono.
- Removida a janela "Sim, tenho autorização" para alvos fora da rede local; no lugar, um aviso na aba Alvo.
- `s` em Resultados salva o histórico inteiro em vez de um relatório só.
- No Linux e no macOS o nscope se reabre com `sudo` ao iniciar e pede a senha, sem precisar de `sudo "$(command -v nscope)"`. Se a senha falhar, abre como usuário comum. `--sem-sudo` desliga.
- Abas Alvo, Comando, Execução e Ajuda reorganizadas: alvo em destaque com validação logo abaixo, resumo do comando em tabela, explicações com recuo alinhado e avisos agrupados por nível, andamento da execução em tabela e Ajuda dividida em tópicos.
- As abas passam a ser 8 (Execução é a 6, Resultados a 7, Ajuda a 8). Em terminais de 80 colunas os nomes ficam abreviados.

### Corrigido
- Backspace não apagava em terminais que mandam `^H` (como o terminal padrão do Kali). Na aba Configurar a mesma tecla trocava de sub-aba.

## [0.1.0] — não publicado

### Adicionado
- TUI em português (ratatui) com 7 abas: Alvo, Perfis, Configurar (9 sub-abas), Comando, Execução, Resultados, Ajuda.
- Catálogo de ~110 opções do nmap como dados, com explicações (o que faz, quando usar, cuidado) e selos de privilégio.
- Barra de comando fixa e colorida, cópia por OSC 52, explicação de cada pedaço, resumo "em palavras simples" e visibilidade estimada.
- 16 perfis prontos; busca global `/`; navegador de scripts NSE.
- Análise antes de executar (erros, avisos, informações) com atalho para a opção responsável.
- Execução do nmap sem shell, progresso, cancelamento, confirmação de autorização e limpeza de temporários.
- Resultados a partir do XML (hosts · portas · detalhes), filtro "só abertas", base de portas, relatório Markdown (`s`), `nscope --open`.
- `--print-command`, `--print-catalog`; `docs/CATALOGO.md` gerado do catálogo.
- NO_COLOR, 16 cores, tamanho mínimo 80x24, mouse opcional, restauração do terminal em pânico/Ctrl+C.
- CI (fmt, clippy, testes em Linux/macOS/Windows, audit, deny) e pipeline de release (binários, SBOM, checksums, atestado) — *o pipeline de release ainda não foi executado*.
