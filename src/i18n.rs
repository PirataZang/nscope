//! Textos da interface em português do Brasil, centralizados para permitir i18n futura.
//! (Os textos de cada opção do nmap ficam em `nmap::catalog`; os de portas em `nmap::knowledge`.)

pub const TABS: [&str; 7] = [
    "Alvo",
    "Perfis",
    "Configurar",
    "Comando",
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

pub const CONFIRM_TITLE: &str = "Confirmação de autorização";
pub const CONFIRM_ASK: &str = "Você tem autorização para escanear estes alvos?";
pub const CONFIRM_NOTE: &str = "Escanear sistemas sem permissão pode ser crime. O padrão é Não.";
pub const CONFIRM_YES: &str = "Sim, tenho autorização";
pub const CONFIRM_NO: &str = "Não";

pub const SEARCH_PROMPT: &str = "Buscar opção: nome, flag ou o que faz (ex.: udp, -sV, firewall)";
pub const SEARCH_NONE: &str = "Nada encontrado.";

pub const RUN_IDLE: &str = "Pronto. Pressione r para executar o comando.";
pub const RUN_RUNNING: &str = "Executando… pressione c para cancelar.";
pub const RUN_CANCELLED: &str = "Cancelado.";
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
        ("Debian / Ubuntu", "sudo apt install nmap"),
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

/// Atalhos do rodapé por tela: (tecla, ação).
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
        3 => vec![("↑↓", "avisos"), ("Enter", "ir à opção"), ("y", "copiar")],
        4 => vec![("r", "executar"), ("c", "cancelar"), ("↑↓", "rolar")],
        5 => vec![
            ("↑↓", "mover"),
            ("←→", "painel"),
            ("o", "só abertas"),
            ("s", "salvar"),
        ],
        _ => vec![("↑↓", "rolar")],
    };
    v.extend([
        ("Tab", "abas"),
        ("/", "buscar"),
        ("r", "executar"),
        ("y", "copiar"),
        ("?", "ajuda"),
        ("q", "sair"),
    ]);
    v
}

pub const FOOTER_EDIT: [(&str, &str); 2] = [("Enter", "confirmar"), ("Esc", "cancelar")];

pub enum Help {
    Heading(&'static str),
    Para(&'static str),
    Item(&'static str, &'static str),
    Blank,
}

pub fn help() -> Vec<Help> {
    use Help::*;
    vec![
        Heading("COMO USAR EM 4 PASSOS"),
        Item(
            "1. Alvo (1)",
            "diga o que escanear: um IP, um nome ou uma rede.",
        ),
        Item(
            "2. Perfis (2) ou Configurar (3)",
            "escolha um perfil pronto ou ajuste opção por opção. Cada opção explica o que faz, quando usar e o que cuidar.",
        ),
        Item(
            "3. Comando (4)",
            "revise o comando final. Cada pedaço é explicado e os avisos aparecem aqui, antes de executar.",
        ),
        Item(
            "4. Execução (5)",
            "pressione r e acompanhe. Depois veja os Resultados (6).",
        ),
        Blank,
        Heading("ATALHOS"),
        Item("Tab / Shift+Tab, 1–7", "trocar de aba principal"),
        Item(
            "← →  ou  [ ]",
            "trocar sub-aba (Configurar) ou painel (Resultados)",
        ),
        Item("↑ ↓  ou  j k", "mover a seleção / rolar"),
        Item(
            "Enter / Espaço",
            "ligar ou desligar, trocar valor, editar texto",
        ),
        Item("Shift+Enter ou -", "valor anterior em opções de escolha"),
        Item("Del", "limpar a opção (volta ao padrão)"),
        Item("/", "buscar qualquer opção por nome, flag ou descrição"),
        Item("r  /  c", "executar / cancelar"),
        Item("y", "copiar o comando (OSC 52)"),
        Item(
            "o  /  s",
            "em Resultados: só portas abertas / salvar relatório Markdown",
        ),
        Item("?", "esta tela"),
        Item("q  /  Ctrl+C", "sair (encerra o scan em andamento)"),
        Item("Mouse", "clique em abas, sub-abas e linhas (opcional)"),
        Blank,
        Heading("ESTADOS DE PORTA"),
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
        Blank,
        Heading("QUAL TÉCNICA ESCOLHER?"),
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
        Blank,
        Heading("PRIVILÉGIOS"),
        Para(
            "Várias técnicas (SYN, UDP, detecção de SO...) precisam de administrador. O nscope detecta isso sozinho e mostra na barra de título. Se precisar, saia e rode com sudo nscope (no Windows, abra o terminal como administrador). O nscope nunca se eleva por conta própria.",
        ),
        Blank,
        Heading("GLOSSÁRIO"),
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
        Blank,
        Heading("USO RESPONSÁVEL (AVISO LEGAL)"),
        Para(
            "Use o nscope apenas em sistemas que você possui ou para os quais tem autorização por escrito. Scans podem ser registrados, bloqueados e, sem permissão, enquadrados como crime. Para praticar, use scanme.nmap.org (o projeto Nmap permite, com moderação) ou um laboratório seu.",
        ),
        Para(
            "A estimativa de visibilidade (ruído) é didática: não garante que um scan passe despercebido.",
        ),
        Blank,
        Heading("INSTALAR O NMAP"),
    ]
}
