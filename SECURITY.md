# Política de segurança

## Como reportar uma vulnerabilidade

Use o **relato privado de vulnerabilidades do GitHub** (aba *Security → Report a vulnerability*) do repositório.
Não abra uma issue pública para falhas de segurança.

Inclua: versão (`nscope --version`), sistema operacional, passos para reproduzir e o impacto que você percebe.

**Prazos que buscamos cumprir:** confirmação em até 5 dias úteis; correção ou plano de mitigação em até 30 dias;
divulgação coordenada junto com a versão corrigida, com crédito a quem reportou (se desejar).

Versões suportadas: apenas a última release.

## Modelo de ameaças (resumo)

O nscope **não** reimplementa o nmap: ele monta argumentos, executa o `nmap` local e mostra o resultado.
A superfície de ataque é o texto que entra (do usuário) e o texto que volta (da rede e do nmap).

| Ameaça | Como o nscope se protege |
|---|---|
| Injeção de comando por alvo ou flag | Nenhum shell em lugar nenhum: `std::process::Command` com argumentos em lista. Alvos e valores passam por lista de permitidos; alvo nunca começa com `-`; campo de flags extras recusa `; & \| \ $ < > ( ) `` ` `` e flags de saída. |
| Injeção de escapes de terminal (banner, hostname, saída de script malicioso) | Todo texto de rede/XML/processo é sanitizado na entrada: controles (inclusive ESC e C1) viram `·`, bidi e largura zero são neutralizados. Há testes para isso. |
| Arquivos temporários previsíveis ou legíveis por outros | Diretório 0700 com nome PID+nanossegundos, criado sem sobrescrever; removido ao terminar, cancelar, sair, falhar ou em pânico (`Drop`). |
| XML hostil (bomba de entidades, arquivo gigante) | `roxmltree` com limites de expansão padrão; arquivos acima de 64 MiB são recusados sem serem lidos; limites de hosts/portas exibidos. |
| Saída infinita do processo | Linhas lidas com limite de 8 KiB; só 5000 linhas ficam em memória; canal limitado. |
| Escanear sem querer o que não é seu | Avisos antes de executar e um aviso na aba Alvo para alvos fora de redes privadas/loopback/documentação/`scanme.nmap.org`. Não há janela de confirmação. |
| Escalada de privilégio | O nscope nunca se eleva sozinho. Você decide rodar com `sudo`. |
| Vazamento de dados | Sem telemetria, sem atualização automática, sem conexões de rede próprias. Nada é gravado sem você pedir (relatório com `s`, e só sem sobrescrever). |
| Cadeia de suprimentos | `Cargo.lock` versionado, `cargo audit` e `cargo deny` no CI, poucas dependências (justificadas no README), ações do CI fixadas por SHA, releases com SBOM CycloneDX, checksums e atestado de build. |

### O que o nscope NÃO protege

- **O nmap em si.** Uma vulnerabilidade no nmap ou nos scripts NSE que você executar continua sendo do nmap.
  Scripts das categorias `intrusive`, `brute`, `dos`, `exploit` e `fuzzer` fazem o que dizem; o nscope só avisa.
- **A autorização legal.** O aviso é um lembrete, não verificação. A responsabilidade é de quem executa.
- **Um sistema já comprometido** (um `nmap` trocado no `PATH`, terminal malicioso etc.).
- **Encerramento forçado** (`SIGKILL`, queda de energia): o diretório temporário (0700, só com o XML do scan) pode ficar em `$TMPDIR`.
  `SIGTERM` também não é tratado; use `q` ou `Ctrl+C`.
- **A privacidade dos arquivos que você mesmo manda salvar** (`-oN`, `-oX`, relatório Markdown): proteja-os como qualquer relatório de pentest.
- **A "visibilidade estimada"** é didática: não garante que um scan passe despercebido.
