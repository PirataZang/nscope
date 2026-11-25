//! Textos da interface em português do Brasil, centralizados para permitir i18n futura.
//! (Os textos de cada opção do nmap ficam em `nmap::catalog`; os de portas em `nmap::knowledge`.)

pub const TABS: [&str; 8] = [
    "Alvo",
    "Perfis",
    "Configurar",
    "Comando",
    "Editar",
    "Execução",
    "Resultados",
    "Ajuda",
];
/// Nomes curtos para terminais estreitos (80 colunas).
pub const TABS_SHORT: [&str; 8] = [
    "Alvo",
    "Perfis",
    "Config",
    "Comando",
    "Editar",
    "Execução",
    "Resultados",
    "Ajuda",
];

pub const TITLE: &str = "nscope";
pub const PRIV_ADMIN: &str = "administrador";
pub const PRIV_USER: &str = "usuário comum";
pub const NMAP_MISSING_SHORT: &str = "nmap não encontrado";

pub const MIN_SIZE: &str = "Janela pequena demais";
pub const MIN_SIZE_HELP: &str = "O nscope precisa de pelo menos 80 colunas por 24 linhas.";
pub const MIN_SIZE_NOW: &str = "Tamanho atual";

pub const PANEL_WHAT: &str = "O que isso faz";
pub const PANEL_COMMAND: &str = "Comando final";
pub const PANEL_PIECES: &str = "Cada pedaço do comando";
pub const PANEL_WARNINGS: &str = "Avisos e problemas";

pub const K_WHAT: &str = "O que faz";
pub const K_WHEN: &str = "Quando usar";
pub const K_CAUTION: &str = "Cuidado";
pub const K_VALUES: &str = "Valores possíveis";
pub const K_EXAMPLES: &str = "Exemplos";
pub const K_USE: &str = "Exemplo de uso";
pub const K_NOW: &str = "Neste momento";
pub const K_PROBLEM: &str = "Problema";
pub const K_HOW: &str = "Como mudar";
pub const K_VALIDATION: &str = "Validação";

pub const BADGE_ROOT: &str = "EXIGE ADMIN";
pub const BADGE_SOFT: &str = "MELHOR COM ADMIN";
pub const BADGE_STANDALONE: &str = "NÃO FAZ SCAN";

pub const HOW_BOOL: &str = "Enter ou Espaço liga e desliga. Del volta ao padrão.";
pub const HOW_CHOICE: &str =
    "Enter troca para o próximo valor; Shift+Enter ou - volta ao anterior. Del volta ao padrão.";
pub const HOW_TEXT: &str = "Enter edita o valor; Enter confirma, Esc cancela. Del limpa.";
pub const HOW_NSE: &str = "Enter ou Espaço adiciona ou remove este item da lista de --script.";
pub const OFF_NOTE: &str = "desligado: não entra no comando";

pub const SEARCH_PROMPT: &str = "Buscar opção: nome, flag ou o que faz (ex.: udp, -sV, firewall)";
pub const SEARCH_NONE: &str = "Nada encontrado.";

pub const RUN_IDLE: &str = "Pronto para executar. Pressione r.";
pub const RUN_RUNNING: &str = "Executando. Pressione c para cancelar.";
pub const RUN_CANCELLED: &str = "Cancelado. Pressione r para executar de novo.";
pub const RUN_DONE: &str = "Concluído.";
pub const LOG_EMPTY: &str = "A saída do nmap aparece aqui, linha por linha, como no terminal.";

pub const NO_RESULTS: &str =
    "Nenhum resultado ainda. Execute um scan (r) ou abra um XML com: nscope --open scan.xml";

pub const MSG_COPIED: &str =
    "Comando enviado ao terminal (OSC 52). Se não colou, selecione-o na barra e copie à mão.";
pub const MSG_ALREADY_RUNNING: &str = "Já há um scan em andamento. Pressione c para cancelar.";
pub const MSG_NO_NMAP: &str =
    "O nmap não está instalado ou não está no PATH. Veja como instalar na aba Ajuda (?).";

pub fn install_lines() -> Vec<(&'static str, &'static str)> {
    let all = [
        ("Debian / Ubuntu / Kali", "sudo apt install nmap"),
        ("Fedora / RHEL", "sudo dnf install nmap"),
        ("Arch Linux", "sudo pacman -S nmap"),
        ("macOS (Homebrew)", "brew install nmap"),
        (
            "Windows (winget)",
            "winget install Insecure.Nmap   (instala também o Npcap; ou baixe em nmap.org)",
        ),
    ];
    let mut v: Vec<_> = all.to_vec();
    let first = if cfg!(windows) {
        4
    } else if cfg!(target_os = "macos") {
        3
    } else {
        0
    };
    let item = v.remove(first);
    v.insert(0, item);
    v
}

/// Atalhos do rodapé por tela: (tecla, ação). Os globais entram depois, sem repetir teclas.
pub fn footer(tab: usize) -> Vec<(&'static str, &'static str)> {
    let mut v: Vec<(&str, &str)> = match tab {
        0 => vec![("↑↓", "mover"), ("Enter", "editar"), ("Del", "limpar")],
        1 => vec![("↑↓", "escolher"), ("Enter", "aplicar")],
        2 => vec![
            ("↑↓", "mover"),
            ("←→", "sub-aba"),
            ("Enter", "ligar/editar"),
            ("Del", "limpar"),
        ],
        3 => vec![
            ("↑↓", "avisos"),
            ("Enter", "ir à opção"),
            ("PgUp/PgDn", "rolar pedaços"),
        ],
        4 => vec![("Enter", "editar comando"), ("↑↓", "rolar")],
        5 => vec![
            ("r", "executar"),
            ("c", "cancelar"),
            ("↑↓", "rolar"),
            ("End", "fim"),
        ],
        6 => vec![
            ("↑↓", "mover"),
            ("←→", "painel"),
            ("o", "só abertas"),
            ("s", "salvar histórico"),
        ],
        _ => vec![("↑↓", "tópico"), ("PgUp/PgDn", "rolar")],
    };
    for g in [
        ("Tab", "abas"),
        ("/", "buscar"),
        ("r", "executar"),
        ("y", "copiar"),
        ("?", "ajuda"),
        ("q", "sair"),
    ] {
        if !v.iter().any(|(k, _)| *k == g.0) {
            v.push(g);
        }
    }
    v
}

pub const FOOTER_EDIT: [(&str, &str); 3] = [
    ("Enter", "confirmar"),
    ("Esc", "cancelar"),
    ("Ctrl+U", "apagar tudo"),
];
pub const FOOTER_CMD_EDIT: [(&str, &str); 4] = [
    ("Enter", "aplicar"),
    ("Esc", "desfazer"),
    ("←→ Home End", "mover"),
    ("Ctrl+U", "apagar tudo"),
];

pub enum Help {
    Heading(&'static str),
    Para(&'static str),
    Item(&'static str, &'static str),
    Blank,
}

/// Tópicos da Ajuda: (título, conteúdo). A lista de tópicos fica à esquerda na tela.
pub fn help() -> Vec<(&'static str, Vec<Help>)> {
    use Help::*;
    vec![
        (
            "Primeiros passos",
            vec![
                Para("O caminho normal é ir da aba 1 até a 7, nesta ordem:"),
                Blank,
                Item("1 Alvo", "diga o que escanear: um IP, um nome ou uma rede."),
                Item(
                    "2 Perfis",
                    "escolha uma receita pronta. ★ Padrão com serviços é um bom começo.",
                ),
                Item(
                    "3 Configurar",
                    "ajuste opção por opção, se quiser. Cada uma explica o que faz, quando usar e o cuidado.",
                ),
                Item(
                    "4 Comando",
                    "revise o comando final. Cada pedaço é explicado e os avisos aparecem antes de executar.",
                ),
                Item(
                    "5 Editar",
                    "opcional: digite ou cole um comando do nmap e veja a explicação de cada parte.",
                ),
                Item("6 Execução", "pressione r e acompanhe a saída do nmap."),
                Item("7 Resultados", "navegue pelos hosts e portas encontrados."),
                Blank,
                Para("O comando montado fica sempre visível na barra de baixo, em qualquer aba."),
            ],
        ),
        (
            "Atalhos de teclado",
            vec![
                Heading("Em qualquer aba"),
                Item("Tab  Shift+Tab", "próxima / aba anterior"),
                Item("1 a 8", "ir direto para a aba"),
                Item("↑ ↓  ou  j k", "mover a seleção ou rolar"),
                Item("/", "buscar qualquer opção por nome, flag ou descrição"),
                Item("r  c", "executar / cancelar o scan"),
                Item("y", "copiar o comando (OSC 52)"),
                Item("?", "abrir esta Ajuda"),
                Item("q  Ctrl+C", "sair (encerra o scan em andamento)"),
                Blank,
                Heading("Nas listas de opções (Alvo e Configurar)"),
                Item(
                    "Enter  Espaço",
                    "ligar ou desligar, trocar valor, editar texto",
                ),
                Item("Shift+Enter  -", "valor anterior em opções de escolha"),
                Item("Del  Backspace", "limpar a opção (volta ao padrão)"),
                Item("← →  ou  [ ]", "trocar sub-aba em Configurar"),
                Blank,
                Heading("Ao digitar um texto"),
                Item("Enter", "confirmar"),
                Item("Esc", "cancelar e voltar ao valor anterior"),
                Item(
                    "Backspace  Del",
                    "apagar o caractere antes / depois do cursor",
                ),
                Item("← →  Home  End", "mover o cursor"),
                Item("Ctrl+U", "apagar tudo"),
                Blank,
                Heading("Em Resultados"),
                Item("← →", "trocar entre execuções, hosts e portas"),
                Item(
                    "↑ ↓ em Execuções",
                    "ver o resultado de outra execução desta sessão",
                ),
                Item("o", "mostrar só portas abertas"),
                Item(
                    "s",
                    "salvar o histórico inteiro numa pasta nscope-historico-<data>, na pasta onde o terminal foi aberto",
                ),
                Blank,
                Item("Mouse", "clique em abas, sub-abas e linhas (opcional)"),
            ],
        ),
        (
            "Estados de porta",
            vec![
                Item("open", "há um serviço escutando e aceitando conexões"),
                Item(
                    "closed",
                    "a porta responde, mas nenhum serviço está escutando",
                ),
                Item(
                    "filtered",
                    "um firewall bloqueia: o nmap não consegue saber se está aberta",
                ),
                Item(
                    "unfiltered",
                    "acessível, mas sem saber se aberta ou fechada (típico do ACK scan)",
                ),
                Item(
                    "open|filtered",
                    "não dá para distinguir entre aberta e filtrada (comum em UDP, Null/FIN/Xmas)",
                ),
                Item(
                    "closed|filtered",
                    "não dá para distinguir entre fechada e filtrada (típico do idle scan)",
                ),
            ],
        ),
        (
            "Qual técnica escolher",
            vec![
                Item(
                    "Não sei",
                    "deixe em Automático: com administrador usa SYN, sem usa conexão completa",
                ),
                Item("Só ver quem está ligado", "-sn (Só descobrir hosts)"),
                Item("Entender o firewall", "-sA (ACK): mostra o que é filtrado"),
                Item(
                    "Achar DNS, SNMP, VPN",
                    "-sU (UDP), junto com --top-ports para não demorar",
                ),
                Item(
                    "Passar sem ser notado",
                    "veja a sub-aba Evasão e use só em testes autorizados",
                ),
            ],
        ),
        (
            "Privilégios",
            vec![
                Para(
                    "Várias técnicas (SYN, UDP, detecção de SO...) precisam de administrador. O nscope detecta isso sozinho e mostra no canto superior direito.",
                ),
                Blank,
                Item(
                    "Linux / macOS",
                    "saia e abra o nscope de novo (sem --sem-sudo) para ele pedir a senha",
                ),
                Item(
                    "Windows",
                    "abra o Windows Terminal como administrador e rode nscope",
                ),
                Blank,
                Para("No Linux e no macOS o nscope pede a senha do sudo ao abrir."),
                Para(
                    "Com sudo, os arquivos salvos (histórico e saídas do nmap) continuam sendo do seu usuário, não do root.",
                ),
            ],
        ),
        (
            "Glossário",
            vec![
                Item(
                    "SYN / ACK / RST",
                    "mensagens do TCP: SYN pede uma conexão, ACK confirma, RST recusa",
                ),
                Item(
                    "CIDR (/24)",
                    "jeito de escrever uma rede: 192.168.0.0/24 são os 256 endereços de 192.168.0.0 a 192.168.0.255",
                ),
                Item(
                    "Banner",
                    "texto que um serviço mostra ao ser acessado, geralmente com nome e versão",
                ),
                Item(
                    "NSE",
                    "Nmap Scripting Engine: scripts em Lua que ampliam o nmap",
                ),
                Item(
                    "IDS / IPS",
                    "sistemas que detectam (e bloqueiam) comportamento de ataque na rede",
                ),
                Item("RTT", "tempo de ida e volta de um pacote"),
                Item(
                    "DNS reverso",
                    "descobrir o nome de uma máquina a partir do IP",
                ),
            ],
        ),
        (
            "Uso responsável",
            vec![
                Para(
                    "Use o nscope apenas em sistemas que você possui ou para os quais tem autorização por escrito. Scans podem ser registrados, bloqueados e, sem permissão, enquadrados como crime.",
                ),
                Blank,
                Para(
                    "Para praticar, use scanme.nmap.org (o projeto Nmap permite, com moderação) ou um laboratório seu.",
                ),
                Blank,
                Para(
                    "A estimativa de visibilidade (ruído) é didática: não garante que um scan passe despercebido.",
                ),
            ],
        ),
        ("Instalar o nmap", {
            let mut v: Vec<Help> = install_lines()
                .into_iter()
                .map(|(os, cmd)| Item(os, cmd))
                .collect();
            v.push(Blank);
            v.push(Para(
                "Sem o nmap você ainda pode montar, explicar e copiar comandos (y).",
            ));
            v
        }),
    ]
}
