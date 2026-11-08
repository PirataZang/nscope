# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/); versionamento semântico.

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
