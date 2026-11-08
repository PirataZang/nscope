//! Catálogo de opções do nmap: cada opção é um dado (não código espalhado).
//! Textos escritos em português simples; revisar a cada versão do nmap (testado com 7.9x).

use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Section {
    Alvo,
    Descoberta,
    Tecnica,
    Portas,
    Servicos,
    Scripts,
    Tempo,
    Evasao,
    Saida,
    Avancado,
}

impl Section {
    /// Sub-abas da tela Configurar, na ordem de exibição.
    pub const CONFIG: [Section; 9] = [
        Section::Descoberta,
        Section::Tecnica,
        Section::Portas,
        Section::Servicos,
        Section::Scripts,
        Section::Tempo,
        Section::Evasao,
        Section::Saida,
        Section::Avancado,
    ];
    /// Ordem em que as opções entram no comando (alvo: -iL/-iR/excludes, depois os posicionais).
    pub const EMIT_ORDER: [Section; 10] = [
        Section::Tecnica,
        Section::Descoberta,
        Section::Portas,
        Section::Servicos,
        Section::Scripts,
        Section::Tempo,
        Section::Evasao,
        Section::Saida,
        Section::Avancado,
        Section::Alvo,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Section::Alvo => "Alvo",
            Section::Descoberta => "Descoberta de hosts",
            Section::Tecnica => "Técnica de scan",
            Section::Portas => "Portas",
            Section::Servicos => "Serviços e SO",
            Section::Scripts => "Scripts (NSE)",
            Section::Tempo => "Tempo e desempenho",
            Section::Evasao => "Evasão e firewall",
            Section::Saida => "Saída e relatórios",
            Section::Avancado => "Avançado",
        }
    }
    pub fn short(self) -> &'static str {
        match self {
            Section::Alvo => "Alvo",
            Section::Descoberta => "Descoberta",
            Section::Tecnica => "Técnica",
            Section::Portas => "Portas",
            Section::Servicos => "Serviços e SO",
            Section::Scripts => "Scripts",
            Section::Tempo => "Tempo",
            Section::Evasao => "Evasão",
            Section::Saida => "Saída",
            Section::Avancado => "Avançado",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Bool,
    Text,
    Number,
    Choice,
}

/// Necessidade de privilégios de administrador.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Root {
    None,
    /// Funciona pior (ou usa alternativa) sem admin.
    Soft,
    /// Exige admin.
    Hard,
}

/// Como o valor entra no comando.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fmt {
    /// `-g 53` (dois argumentos)
    Sep,
    /// `-PS22,80` (colado)
    Cat,
    /// `--script=x`
    Eq,
    /// alvos posicionais (último)
    Positional,
    /// flags extras: cada pedaço vira um argumento
    Raw,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Validator {
    Free,
    Int { min: u64, max: u64 },
    IntMul { min: u64, max: u64, mul: u64 },
    Time,
    Ports,
    Protos,
    Ratio,
    Hex,
    ScanFlags,
    Mac,
    Decoys,
}

/// Mostra a opção só quando outra opção tem um valor específico.
#[derive(Clone, Copy, Debug)]
pub struct Cond {
    pub id: &'static str,
    pub is: &'static str,
}

#[derive(Clone, Debug)]
pub struct Choice {
    pub id: &'static str,
    pub label: &'static str,
    /// Flag emitida (pode ser vazia).
    pub flag: &'static str,
    pub what: &'static str,
    pub root: Root,
    /// Id de outra opção que fornece o argumento da flag (ex.: -sI usa `zombie`).
    pub arg_from: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct Opt {
    pub id: &'static str,
    pub section: Section,
    pub kind: Kind,
    pub flag: &'static str,
    pub label: &'static str,
    pub what: &'static str,
    pub when: &'static str,
    pub caution: &'static str,
    pub placeholder: &'static str,
    pub examples: Vec<(&'static str, &'static str)>,
    pub fmt: Fmt,
    pub root: Root,
    pub validator: Validator,
    pub visible_if: Option<Cond>,
    pub standalone: bool,
    pub choices: Vec<Choice>,
    pub default: &'static str,
    /// Campo auxiliar: guarda valor mas quem emite é outra opção (via `arg_from`).
    pub helper: bool,
}

impl Opt {
    fn new(
        section: Section,
        id: &'static str,
        kind: Kind,
        flag: &'static str,
        label: &'static str,
        what: &'static str,
    ) -> Self {
        Opt {
            id,
            section,
            kind,
            flag,
            label,
            what,
            when: "",
            caution: "",
            placeholder: "",
            examples: vec![],
            fmt: Fmt::Sep,
            root: Root::None,
            validator: Validator::Free,
            visible_if: None,
            standalone: false,
            choices: vec![],
            default: "",
            helper: false,
        }
    }
    fn when(mut self, s: &'static str) -> Self {
        self.when = s;
        self
    }
    fn caution(mut self, s: &'static str) -> Self {
        self.caution = s;
        self
    }
    fn ph(mut self, s: &'static str) -> Self {
        self.placeholder = s;
        self
    }
    fn ex(mut self, e: &[(&'static str, &'static str)]) -> Self {
        self.examples = e.to_vec();
        self
    }
    fn fmt(mut self, f: Fmt) -> Self {
        self.fmt = f;
        self
    }
    fn root(mut self, r: Root) -> Self {
        self.root = r;
        self
    }
    fn val(mut self, v: Validator) -> Self {
        self.validator = v;
        self
    }
    fn show(mut self, id: &'static str, is: &'static str) -> Self {
        self.visible_if = Some(Cond { id, is });
        self
    }
    fn standalone(mut self) -> Self {
        self.standalone = true;
        self
    }
    fn def(mut self, d: &'static str) -> Self {
        self.default = d;
        self
    }
    fn helper(mut self) -> Self {
        self.helper = true;
        self
    }
    /// Valor atual de `id`, se esta opção é de escolha: id do primeiro `choices` é o padrão.
    pub fn default_value(&self) -> &'static str {
        if self.kind == Kind::Choice {
            self.choices[0].id
        } else {
            self.default
        }
    }
    pub fn choice(&self, id: &str) -> Option<&Choice> {
        self.choices.iter().find(|c| c.id == id)
    }
}

fn b(
    s: Section,
    id: &'static str,
    flag: &'static str,
    label: &'static str,
    what: &'static str,
) -> Opt {
    Opt::new(s, id, Kind::Bool, flag, label, what)
}
fn t(
    s: Section,
    id: &'static str,
    flag: &'static str,
    label: &'static str,
    what: &'static str,
) -> Opt {
    Opt::new(s, id, Kind::Text, flag, label, what)
}
fn n(
    s: Section,
    id: &'static str,
    flag: &'static str,
    label: &'static str,
    what: &'static str,
    min: u64,
    max: u64,
) -> Opt {
    Opt::new(s, id, Kind::Number, flag, label, what).val(Validator::Int { min, max })
}
fn tm(
    s: Section,
    id: &'static str,
    flag: &'static str,
    label: &'static str,
    what: &'static str,
) -> Opt {
    t(s, id, flag, label, what).val(Validator::Time)
}
fn c(
    s: Section,
    id: &'static str,
    label: &'static str,
    what: &'static str,
    choices: Vec<Choice>,
) -> Opt {
    let mut o = Opt::new(s, id, Kind::Choice, "", label, what);
    o.choices = choices;
    o
}
fn ch(id: &'static str, label: &'static str, flag: &'static str, what: &'static str) -> Choice {
    Choice {
        id,
        label,
        flag,
        what,
        root: Root::None,
        arg_from: None,
    }
}
impl Choice {
    fn hard(mut self) -> Self {
        self.root = Root::Hard;
        self
    }
    fn arg(mut self, id: &'static str) -> Self {
        self.arg_from = Some(id);
        self
    }
}

use Root::{Hard, Soft};
use Section::*;

fn build() -> Vec<Opt> {
    vec![
        // ---------- ALVO ----------
        t(Alvo, "targets", "", "Alvos", "Quem será escaneado: um IP, um nome de máquina, uma rede inteira (CIDR) ou uma faixa. Separe vários alvos com espaço ou vírgula.")
            .fmt(Fmt::Positional).def("scanme.nmap.org").ph("scanme.nmap.org 192.168.0.0/24")
            .when("Sempre, a não ser que você use uma lista em arquivo (-iL) ou alvos aleatórios (-iR).")
            .caution("Escaneie apenas o que você possui ou tem autorização por escrito para testar. Para praticar, o projeto Nmap permite escanear scanme.nmap.org.")
            .ex(&[("192.168.0.10", "um único IP"), ("servidor.local", "um nome de máquina (DNS)"), ("192.168.0.0/24", "a rede inteira: 256 endereços"),
                  ("192.168.0.1-50", "uma faixa de IPs"), ("192.168.0-3.1", "octeto variável: quatro redes"), ("10.0.0.5 10.0.0.9", "vários alvos, separados por espaço ou vírgula"),
                  ("2001:db8::1", "um endereço IPv6 (use também -6)")]),
        t(Alvo, "iL", "-iL", "Lista de alvos em arquivo", "Lê os alvos de um arquivo de texto (um por linha ou separados por espaço). Use \"-\" para ler da entrada padrão.")
            .ph("alvos.txt").when("Listas grandes ou geradas por outra ferramenta."),
        n(Alvo, "iR", "-iR", "Alvos aleatórios", "Escolhe N endereços IP aleatórios da internet para escanear.", 1, 1_000_000)
            .ph("10").caution("Escanear a internet ao acaso gera denúncias de abuso e pode ser ilegal. Evite, a menos que seja uma pesquisa autorizada."),
        t(Alvo, "exclude", "--exclude", "Excluir alvos", "Retira hosts ou redes do scan (separe por vírgula). Ideal para proteger o seu próprio IP ou servidores críticos que não podem ser incomodados.")
            .ph("192.168.0.1,192.168.0.254"),
        t(Alvo, "excludefile", "--excludefile", "Excluir alvos (arquivo)", "Igual a --exclude, mas lê a lista de um arquivo.").ph("excluir.txt"),

        // ---------- DESCOBERTA ----------
        b(Descoberta, "Pn", "-Pn", "Pular a descoberta de hosts", "Escaneia as portas mesmo que o host não responda ao teste \"você está ligado?\". Trata todos os alvos como ligados.")
            .when("Quando o nmap diz \"Host seems down\" mas você sabe que o alvo existe (firewalls que bloqueiam ping).")
            .caution("Em faixas grandes fica lento: o nmap gasta tempo com endereços que nem existem."),
        t(Descoberta, "PS", "-PS", "Ping TCP SYN (portas)", "Envia um SYN às portas indicadas. Qualquer resposta (SYN/ACK ou RST) prova que o host está ligado.")
            .fmt(Fmt::Cat).val(Validator::Ports).root(Soft).ph("22,80,443").when("Quando o ping comum (ICMP) é bloqueado. Escolha portas que o alvo costuma ter abertas."),
        t(Descoberta, "PA", "-PA", "Ping TCP ACK (portas)", "Envia um ACK; hosts ligados respondem com RST. Passa por firewalls simples que só bloqueiam conexões novas (SYN).")
            .fmt(Fmt::Cat).val(Validator::Ports).root(Soft).ph("80").when("Combine com -PS para aumentar as chances de achar o host."),
        t(Descoberta, "PU", "-PU", "Ping UDP (portas)", "Envia um pacote UDP; um host ligado costuma responder \"porta inacessível\" (ICMP).")
            .fmt(Fmt::Cat).val(Validator::Ports).root(Hard).ph("40125"),
        t(Descoberta, "PY", "-PY", "Ping SCTP INIT (portas)", "Descobre hosts que usam o protocolo SCTP (comum em telecom).")
            .fmt(Fmt::Cat).val(Validator::Ports).root(Hard).ph("80"),
        b(Descoberta, "PE", "-PE", "Ping ICMP echo", "O \"ping\" clássico: pergunta \"você está aí?\" por ICMP echo request. Já faz parte da descoberta padrão em redes locais.").root(Soft),
        b(Descoberta, "PP", "-PP", "Ping ICMP timestamp", "Pede a hora ao host por ICMP. Alguns firewalls bloqueiam o echo, mas deixam esta consulta passar.").root(Soft),
        b(Descoberta, "PM", "-PM", "Ping ICMP máscara de rede", "Pede a máscara de rede por ICMP address mask. Mais um jeito de achar hosts que ignoram o ping comum.").root(Soft),
        t(Descoberta, "PO", "-PO", "Ping por protocolo IP", "Envia pacotes IP com os números de protocolo indicados (1 = ICMP, 2 = IGMP, 4 = IP-in-IP).")
            .fmt(Fmt::Cat).val(Validator::Protos).root(Hard).ph("1,2,4"),
        c(Descoberta, "dns", "Resolução de DNS", "Controla se o nmap consulta o DNS para trocar IPs por nomes (DNS reverso).", vec![
            ch("padrao", "Padrão (só quando necessário)", "", "O nmap resolve o nome dos hosts que estão ligados."),
            ch("n", "Nunca (-n)", "-n", "Não consulta DNS. Fica mais rápido e mais discreto; você verá só IPs."),
            ch("R", "Sempre (-R)", "-R", "Resolve o DNS reverso de todos os IPs, inclusive dos desligados."),
        ]).when("Use -n em redes grandes ou quando só o IP importa. Use -R quando quiser nomes de tudo."),
        t(Descoberta, "dnsservers", "--dns-servers", "Servidores DNS próprios", "Usa estes servidores DNS (separe por vírgula) em vez dos configurados no sistema.").ph("1.1.1.1,9.9.9.9"),
        b(Descoberta, "systemdns", "--system-dns", "Usar o DNS do sistema", "Usa a resolução de nomes do sistema operacional. Mais lento, mas respeita /etc/hosts e o DNS interno da empresa."),
        b(Descoberta, "traceroute", "--traceroute", "Traçar a rota até o alvo", "Mostra por quais roteadores o tráfego passa até chegar ao alvo (cada passagem é um \"salto\").")
            .root(Hard).when("Para entender a topologia da rede ou descobrir onde o caminho é bloqueado.").caution("Adiciona tempo ao scan."),

        // ---------- TÉCNICA ----------
        c(Tecnica, "tec", "Técnica principal", "Define COMO o nmap testa cada porta (ou se ele só descobre hosts). É a escolha mais importante do scan.", vec![
            ch("auto", "Automático", "", "O nmap decide: usa SYN (-sS) se você é administrador; senão usa conexão completa (-sT)."),
            ch("sL", "Só listar alvos (-sL)", "-sL", "List Scan: apenas lista e resolve os alvos, sem enviar nenhum pacote a eles. Ótimo para conferir o escopo antes de escanear."),
            ch("sn", "Só descobrir hosts (-sn)", "-sn", "Ping scan: descobre quais hosts estão ligados, sem escanear portas. Primeiro passo para mapear uma rede."),
            ch("sS", "TCP SYN (-sS)", "-sS", "Scan \"meio-aberto\": envia SYN e, se vier SYN/ACK, não completa a conexão. Rápido e pouco registrado nos logs.").hard(),
            ch("sT", "TCP conexão completa (-sT)", "-sT", "Abre conexões TCP completas pelo sistema operacional. Funciona sem privilégios, mas é mais lento e deixa mais rastros."),
            ch("sA", "TCP ACK (-sA)", "-sA", "Não descobre portas abertas: mapeia regras de firewall, dizendo se as portas são \"filtradas\" ou \"não filtradas\".").hard(),
            ch("sW", "TCP Window (-sW)", "-sW", "Parecido com o ACK, mas examina o tamanho da janela TCP; em alguns sistemas separa aberta de fechada.").hard(),
            ch("sM", "TCP Maimon (-sM)", "-sM", "Envia FIN/ACK. Só funciona em alguns sistemas BSD antigos; útil em cenários muito específicos.").hard(),
            ch("sN", "TCP Null (-sN)", "-sN", "Pacote TCP sem nenhuma flag. Portas fechadas respondem RST; abertas ficam em silêncio. Tenta driblar firewalls sem estado.").hard(),
            ch("sF", "TCP FIN (-sF)", "-sF", "Envia só a flag FIN. Mesma lógica do Null scan.").hard(),
            ch("sX", "TCP Xmas (-sX)", "-sX", "Liga as flags FIN, PSH e URG (\"árvore de Natal\"). Mesma lógica do Null scan.").hard(),
            ch("sY", "SCTP INIT (-sY)", "-sY", "O \"SYN scan\" do protocolo SCTP, usado em telecom.").hard(),
            ch("sZ", "SCTP COOKIE-ECHO (-sZ)", "-sZ", "Variação mais furtiva do scan SCTP.").hard(),
            ch("sO", "Protocolos IP (-sO)", "-sO", "Descobre quais protocolos IP (ICMP, TCP, UDP, GRE...) o alvo aceita, em vez de portas.").hard(),
            ch("sI", "Idle / zumbi (-sI)", "-sI", "Escaneia usando um \"zumbi\" como intermediário; seu IP não aparece para o alvo. Avançado e raramente funciona hoje.").hard().arg("zombie"),
            ch("b", "FTP bounce (-b)", "-b", "Usa um servidor FTP vulnerável como intermediário. Técnica antiga: quase todos os servidores já bloqueiam.").arg("relay"),
        ]).when("Na dúvida, deixe em Automático. Use ACK para entender firewalls e Null/FIN/Xmas só para testar filtros sem estado.")
          .caution("Null, FIN, Xmas e Maimon geram resultados \"open|filtered\" (ambíguos), e sistemas Windows costumam não seguir o padrão."),
        t(Tecnica, "zombie", "-sI", "Host zumbi", "O host intermediário usado no idle scan. Precisa estar ocioso e ter um contador de IP ID previsível. Formato: host[:porta].")
            .ph("192.0.2.50:80").show("tec", "sI").helper(),
        t(Tecnica, "relay", "-b", "Servidor FTP relay", "O servidor FTP usado como intermediário. Formato: usuario:senha@servidor:porta.")
            .ph("anonymous:x@ftp.exemplo.test:21").show("tec", "b").helper(),
        b(Tecnica, "sU", "-sU", "Escanear também UDP", "Testa portas UDP (DNS 53, SNMP 161, DHCP, NTP...). Pode ser combinado com uma técnica TCP. Sozinho, escaneia só UDP.")
            .root(Hard).when("Para achar DNS, SNMP, VPNs e serviços de rede que não usam TCP.")
            .caution("UDP é lento: portas fechadas só respondem cerca de uma vez por segundo. Combine com -F ou --top-ports."),
        t(Tecnica, "scanflags", "--scanflags", "Flags TCP personalizadas", "Monte seu próprio pacote TCP escolhendo as flags (URG, ACK, PSH, RST, SYN, FIN) ou um número. Substitui as flags da técnica TCP escolhida.")
            .val(Validator::ScanFlags).root(Hard).ph("URGACKPSHRSTSYNFIN").when("Para testar firewalls e pilhas TCP com combinações incomuns."),

        // ---------- PORTAS ----------
        c(Portas, "pmode", "Quais portas escanear", "Cada serviço de rede escuta em uma porta (web: 80/443, SSH: 22). Aqui você escolhe quantas e quais testar.", vec![
            ch("def", "Padrão: 1000 mais comuns", "", "Cobre as 1000 portas mais usadas, segundo a base do nmap. Serve para a maioria dos casos."),
            ch("F", "Rápido: 100 mais comuns (-F)", "-F", "Testa só as 100 portas mais comuns. Bem mais rápido, mas pode perder serviços incomuns."),
            ch("all", "Todas as 65535 (-p-)", "-p-", "Testa todas as portas. Acha serviços escondidos em portas altas, mas demora bem mais."),
            ch("lista", "Lista ou faixa (-p)", "-p", "Você escolhe: 22,80,443 ou 1-1024 ou T:80,U:53 (T = TCP, U = UDP).").arg("plist"),
            ch("top", "N mais comuns (--top-ports)", "--top-ports", "As N portas mais frequentes segundo a base de dados do nmap.").arg("topn"),
            ch("ratio", "Por frequência (--port-ratio)", "--port-ratio", "Testa portas cuja frequência de uso é maior que a razão informada (0.0 a 1.0).").arg("ratio"),
        ]).when("Padrão para começar; \"Todas\" quando precisa de cobertura total; \"Lista\" quando já sabe o que procura.")
          .caution("Todas as 65535 portas podem levar muitos minutos e geram bastante tráfego."),
        t(Portas, "plist", "-p", "Lista de portas", "Portas exatas a testar. Aceita números, faixas e prefixos de protocolo.")
            .val(Validator::Ports).ph("22,80,443").show("pmode", "lista").helper()
            .ex(&[("22,80,443", "três portas específicas"), ("1-1024", "as portas \"privilegiadas\""), ("T:80,U:53", "TCP 80 e UDP 53 (use com -sU)"), ("-", "todas, igual a -p-")]),
        n(Portas, "topn", "--top-ports", "Quantidade de portas", "Quantas das portas mais comuns testar.", 1, 65535).ph("100").def("100").show("pmode", "top").helper(),
        t(Portas, "ratio", "--port-ratio", "Razão de frequência", "Número entre 0.0 e 1.0. Quanto maior, menos portas (só as mais comuns).")
            .val(Validator::Ratio).ph("0.5").def("0.5").show("pmode", "ratio").helper(),
        t(Portas, "exclports", "--exclude-ports", "Excluir portas", "Pula estas portas mesmo que estejam dentro da faixa escolhida. Útil para evitar portas que travam equipamentos frágeis.")
            .val(Validator::Ports).ph("9100,515").when("Impressoras de rede costumam travar ao receber tráfego na porta 9100."),
        b(Portas, "r", "-r", "Portas em ordem sequencial", "Não embaralha a ordem das portas. Por padrão o nmap as embaralha para distribuir a carga e dificultar a detecção."),

        // ---------- SERVIÇOS E SO ----------
        b(Servicos, "sV", "-sV", "Detectar serviço e versão", "Além de saber que a porta está aberta, pergunta ao serviço quem ele é: \"nginx 1.18\" em vez de só \"http\". Essencial para achar software desatualizado.")
            .when("Quase sempre. É a opção que mais enriquece o resultado.").caution("Aumenta o tempo e o tráfego, porque conversa de verdade com cada porta aberta."),
        n(Servicos, "vint", "--version-intensity", "Intensidade da detecção (0 a 9)", "Quão fundo o nmap tenta identificar o serviço. 0 usa só as sondas mais prováveis; 9 tenta todas. O padrão é 7.", 0, 9).ph("7"),
        b(Servicos, "vlight", "--version-light", "Detecção leve (intensidade 2)", "Atalho para --version-intensity 2: rápido, identifica os serviços mais óbvios."),
        b(Servicos, "vall", "--version-all", "Detecção exaustiva (intensidade 9)", "Atalho para --version-intensity 9: tenta todas as sondas em cada porta aberta. Lento, porém o mais completo."),
        b(Servicos, "vtrace", "--version-trace", "Mostrar detalhes da detecção", "Imprime o que o nmap enviou e recebeu durante a detecção de versão. Para depurar resultados estranhos."),
        b(Servicos, "O", "-O", "Detectar sistema operacional", "Analisa detalhes do tráfego TCP/IP (a \"impressão digital\") para adivinhar se o alvo é Linux, Windows, roteador etc.")
            .root(Hard).when("Para inventariar uma rede.").caution("É uma estimativa e pode errar. Funciona melhor quando há ao menos uma porta aberta e uma fechada."),
        b(Servicos, "osl", "--osscan-limit", "Limitar a detecção de SO", "Só tenta detectar o SO em hosts promissores (com ao menos uma porta aberta e uma fechada). Economiza tempo em redes grandes. Exige -O."),
        b(Servicos, "osg", "--osscan-guess", "Palpites de SO mais agressivos", "Mostra palpites mesmo quando a confiança é baixa. Exige -O."),
        b(Servicos, "A", "-A", "Modo agressivo (tudo junto)", "Atalho que liga detecção de SO (-O), de versão (-sV), scripts padrão (-sC) e traceroute (--traceroute).")
            .root(Hard).when("Para um reconhecimento completo de alvos que você está autorizado a testar.").caution("Barulhento e demorado: aparece bastante nos logs e em sistemas de detecção."),

        // ---------- SCRIPTS ----------
        b(Scripts, "sC", "-sC", "Scripts padrão (categoria default)", "Roda os scripts NSE da categoria \"default\": leem banners, certificados TLS, títulos de sites, métodos HTTP e outras informações úteis, sem tentar invadir nada.")
            .when("Para obter mais contexto sobre cada serviço.").caution("Gera mais tráfego e aparece nos logs do alvo."),
        t(Scripts, "script", "--script", "Scripts específicos", "Roda scripts NSE por nome, categoria (default, safe, vuln...), padrão com * ou caminho. Combine com vírgula; use and, or e not para expressões. Use o navegador de scripts abaixo (Enter/Espaço) para montar a lista.")
            .fmt(Fmt::Eq).ph("default,safe")
            .caution("Categorias como brute, dos, exploit, fuzzer e intrusive podem derrubar serviços, bloquear contas e gerar alertas. Só com autorização expressa.")
            .ex(&[("http-title", "um script pelo nome"), ("default,safe", "duas categorias"), ("\"http-*\"", "todos os scripts http-*"), ("\"not intrusive\"", "tudo, menos os intrusivos")]),
        t(Scripts, "scriptargs", "--script-args", "Argumentos dos scripts", "Passa parâmetros aos scripts no formato chave=valor, separados por vírgula.").fmt(Fmt::Eq).ph("http.useragent=Mozilla/5.0"),
        t(Scripts, "scriptargsfile", "--script-args-file", "Argumentos dos scripts (arquivo)", "Lê os argumentos dos scripts de um arquivo.").fmt(Fmt::Eq).ph("args.txt"),
        b(Scripts, "scripttrace", "--script-trace", "Rastrear a comunicação dos scripts", "Mostra todos os dados enviados e recebidos pelos scripts. Para depurar."),
        b(Scripts, "scriptupdatedb", "--script-updatedb", "Atualizar a base de scripts", "Reconstrói o índice de scripts (script.db). Rode depois de instalar scripts novos. Não faz scan.").standalone(),
        t(Scripts, "scripthelp", "--script-help", "Ajuda de um script", "Mostra a descrição de um script (ou de uma categoria) e sai, sem escanear nada.").fmt(Fmt::Eq).ph("http-title").standalone(),

        // ---------- TEMPO ----------
        c(Tempo, "T", "Modelo de velocidade (-T)", "Um atalho que ajusta vários tempos e limites de uma vez. Quanto maior o número, mais rápido e mais barulhento.", vec![
            ch("def", "Normal (T3, padrão)", "", "Equilíbrio entre velocidade e segurança. É o padrão do nmap."),
            ch("T0", "Paranoico (-T0)", "-T0", "Espera cerca de 5 minutos entre sondas. Serve para driblar sistemas de detecção, mas um scan pode levar dias."),
            ch("T1", "Furtivo (-T1)", "-T1", "Espera cerca de 15 segundos entre sondas. Muito lento."),
            ch("T2", "Educado (-T2)", "-T2", "Reduz a velocidade para usar menos banda e menos recursos do alvo (espera cerca de 0,4 s)."),
            ch("T4", "Agressivo (-T4)", "-T4", "Assume uma rede rápida e confiável. Bom para redes locais e laboratórios."),
            ch("T5", "Insano (-T5)", "-T5", "Velocidade máxima sacrificando precisão. Pode perder portas e derrubar equipamentos frágeis."),
        ]).when("T4 é comum em redes locais confiáveis. T2 ou menos para reduzir a chance de detecção.")
          .caution("T4 e T5 podem sobrecarregar equipamentos frágeis e perder portas em redes lentas ou com firewall."),
        n(Tempo, "minhg", "--min-hostgroup", "Mín. de hosts por grupo", "O nmap escaneia hosts em grupos. Define o tamanho mínimo do grupo (mais hosts em paralelo).", 1, 65535).ph("64"),
        n(Tempo, "maxhg", "--max-hostgroup", "Máx. de hosts por grupo", "Limita o tamanho do grupo de hosts escaneados ao mesmo tempo. Útil para ver resultados mais cedo.", 1, 65535).ph("32"),
        n(Tempo, "minpar", "--min-parallelism", "Mín. de sondas em paralelo", "Força um mínimo de sondas simultâneas por grupo. Acelera, com risco de perder precisão.", 1, 65535).ph("10"),
        n(Tempo, "maxpar", "--max-parallelism", "Máx. de sondas em paralelo", "Limita sondas simultâneas. Use 1 para enviar uma sonda por vez (lento e discreto).", 1, 65535).ph("1"),
        tm(Tempo, "minrtt", "--min-rtt-timeout", "Tempo mínimo de espera por resposta", "Menor tempo que o nmap espera por uma resposta antes de reenviar a sonda.").ph("100ms"),
        tm(Tempo, "maxrtt", "--max-rtt-timeout", "Tempo máximo de espera por resposta", "Maior tempo que o nmap espera por uma resposta. Reduza em redes locais rápidas.").ph("1s"),
        tm(Tempo, "initrtt", "--initial-rtt-timeout", "Tempo inicial de espera", "Tempo de espera inicial por resposta, antes de o nmap aprender o tempo real da rede.").ph("500ms"),
        n(Tempo, "retries", "--max-retries", "Máx. de retransmissões", "Quantas vezes reenviar uma sonda sem resposta. Menos tentativas = mais rápido, porém pode perder portas.", 0, 100).ph("2"),
        tm(Tempo, "hosttimeout", "--host-timeout", "Tempo limite por host", "Desiste de um host que demorar mais que isso. Evita que um alvo lento trave o scan inteiro.").ph("30m"),
        tm(Tempo, "scandelay", "--scan-delay", "Pausa entre sondas", "Espera este tempo entre cada sonda enviada a um host. Contorna limites de taxa e reduz ruído.").ph("500ms"),
        tm(Tempo, "maxscandelay", "--max-scan-delay", "Pausa máxima entre sondas", "Limite superior para a pausa que o nmap aumenta sozinho quando percebe perda de pacotes.").ph("1s"),
        n(Tempo, "minrate", "--min-rate", "Taxa mínima (pacotes/s)", "Garante que o nmap envie pelo menos esta quantidade de pacotes por segundo.", 1, 10_000_000)
            .ph("1000").caution("Taxas altas podem sobrecarregar a rede e causar perda de resultados."),
        n(Tempo, "maxrate", "--max-rate", "Taxa máxima (pacotes/s)", "Nunca envia mais que isso por segundo. Ótimo para não saturar links lentos.", 1, 10_000_000).ph("100"),
        b(Tempo, "defeatrst", "--defeat-rst-ratelimit", "Ignorar limite de RST", "Alguns alvos limitam quantos pacotes RST enviam, o que atrasa o scan. Esta opção acelera, ao custo de marcar mais portas como \"filtradas\"."),
        b(Tempo, "defeaticmp", "--defeat-icmp-ratelimit", "Ignorar limite de ICMP", "Equivalente para scans UDP: alvos que limitam respostas ICMP \"porta inacessível\". Mais rápido, menos preciso."),

        // ---------- EVASÃO ----------
        b(Evasao, "f", "-f", "Fragmentar pacotes", "Divide os pacotes IP em fragmentos pequenos (8 bytes) para dificultar a análise por firewalls e IDS simples.")
            .root(Hard).caution("Técnica antiga: muitos firewalls modernos remontam os fragmentos. Use só em testes autorizados."),
        Opt::new(Evasao, "mtu", Kind::Number, "--mtu", "Tamanho do fragmento (MTU)", "Define o tamanho dos fragmentos (precisa ser múltiplo de 8). Substitui -f.")
            .val(Validator::IntMul { min: 8, max: 65528, mul: 8 }).root(Hard).ph("16"),
        t(Evasao, "D", "-D", "Iscas (decoys)", "Mistura seu IP real com IPs falsos (\"iscas\") para o alvo não saber qual é o verdadeiro. ME marca a posição do seu IP; RND:n gera n iscas aleatórias.")
            .val(Validator::Decoys).root(Hard).ph("RND:5,ME").caution("As iscas precisam estar ligadas; senão o tráfego parece um SYN flood e pode derrubar o alvo."),
        t(Evasao, "S", "-S", "Falsificar o IP de origem", "Envia os pacotes como se viessem de outro IP. As respostas voltam para esse IP, não para você.")
            .root(Hard).ph("192.0.2.99").caution("Normalmente exige também -e <interface> e -Pn, e só serve se você controlar o caminho de volta."),
        t(Evasao, "e", "-e", "Interface de rede", "Força o uso de uma interface específica (eth0, wlan0...). Útil com mais de uma placa de rede ou com -S.").ph("eth0"),
        n(Evasao, "g", "-g", "Porta de origem fixa", "Usa esta porta como origem dos pacotes (--source-port). Alguns firewalls mal configurados aceitam tráfego vindo da porta 53 (DNS) ou 20 (FTP-data).", 0, 65535).ph("53"),
        t(Evasao, "proxies", "--proxies", "Passar por proxies", "Encaminha as conexões TCP por proxies HTTP ou SOCKS4 (URLs separadas por vírgula).")
            .ph("socks4://127.0.0.1:9050").caution("Só funciona com conexão completa (-sT) e é lento."),
        t(Evasao, "data", "--data", "Payload em hexadecimal", "Anexa estes bytes (em hexadecimal) aos pacotes enviados.").val(Validator::Hex).ph("DEADBEEF"),
        t(Evasao, "datastring", "--data-string", "Payload em texto", "Anexa este texto aos pacotes enviados.").ph("olá"),
        n(Evasao, "datalen", "--data-length", "Dados aleatórios extras", "Anexa N bytes aleatórios aos pacotes, para que não tenham o tamanho típico de um scan do nmap.", 0, 1400).ph("25"),
        t(Evasao, "ipopts", "--ip-options", "Opções do cabeçalho IP", "Envia pacotes com opções IP: R (registrar rota), T (carimbo de tempo), L/S (roteamento de origem) etc.").root(Hard).ph("R"),
        n(Evasao, "ttl", "--ttl", "TTL dos pacotes", "Define o tempo de vida (TTL) dos pacotes IP. Afeta até quantos roteadores eles chegam.", 0, 255).ph("64"),
        t(Evasao, "spoofmac", "--spoof-mac", "Falsificar o MAC", "Usa outro endereço MAC. Valores: 0 (aleatório), um MAC completo, um prefixo ou o nome de um fabricante (Apple, Cisco...).")
            .val(Validator::Mac).root(Hard).ph("0"),
        b(Evasao, "badsum", "--badsum", "Checksum inválido", "Envia pacotes com checksum errado. Um host de verdade descarta; firewalls e IDS mal feitos podem responder, revelando que existem.").root(Hard),

        // ---------- SAÍDA ----------
        t(Saida, "oN", "-oN", "Salvar em texto normal", "Mesmo formato que você vê na tela. Informe um nome de arquivo.").ph("scan.txt"),
        t(Saida, "oX", "-oX", "Salvar em XML", "Formato para programas lerem (e o que o nscope usa para montar os Resultados). Informe um nome de arquivo.").ph("scan.xml"),
        t(Saida, "oG", "-oG", "Salvar em formato grepável", "Uma linha por host, fácil de filtrar com grep. Formato legado: prefira XML.").ph("scan.gnmap"),
        t(Saida, "oS", "-oS", "Salvar em \"script kiddie\"", "Texto em leetspeak (m4s n1ng43m 1550). Só por diversão.").ph("scan.txt"),
        t(Saida, "oA", "-oA", "Salvar nos 3 formatos", "Salva em texto, XML e grepável de uma vez, usando o nome-base informado (cria .nmap, .xml e .gnmap).")
            .ph("relatorio").when("É a opção mais prática: guarde sempre o resultado."),
        c(Saida, "v", "Nível de detalhes (-v)", "Mostra mais informações durante o scan (portas abertas assim que são achadas, estimativas de tempo...).", vec![
            ch("off", "Normal", "", "Saída padrão."),
            ch("v1", "Detalhado (-v)", "-v", "Mostra portas abertas assim que são descobertas e progresso."),
            ch("v2", "Mais detalhado (-vv)", "-vv", "Ainda mais informação sobre o que o nmap está fazendo."),
            ch("v3", "Máximo (-vvv)", "-vvv", "O nível mais verboso."),
        ]),
        c(Saida, "d", "Nível de depuração (-d)", "Mostra informação interna do nmap para investigar problemas.", vec![
            ch("off", "Desligado", "", "Sem depuração."),
            ch("d1", "Básico (-d)", "-d", "Depuração básica."),
            ch("d2", "Intermediário (-dd)", "-dd", "Depuração intermediária."),
            ch("d3", "Intenso (-ddd)", "-ddd", "Depuração intensa."),
        ]),
        b(Saida, "reason", "--reason", "Mostrar o motivo de cada estado", "Explica por que cada porta está aberta, fechada ou filtrada (ex.: \"syn-ack\", \"reset\", \"no-response\").").when("Ótimo para aprender e para depurar resultados estranhos."),
        b(Saida, "open", "--open", "Mostrar só portas abertas", "Esconde portas fechadas e filtradas da saída. Deixa o relatório bem mais limpo."),
        b(Saida, "packettrace", "--packet-trace", "Mostrar todos os pacotes", "Imprime cada pacote enviado e recebido. Muito longo; use em poucas portas para entender o que acontece na rede."),
        b(Saida, "iflist", "--iflist", "Listar interfaces e rotas", "Mostra as interfaces de rede e rotas que o nmap enxerga e sai. Para depurar problemas de rede.").standalone(),
        b(Saida, "append", "--append-output", "Acrescentar ao arquivo", "Adiciona o resultado ao final dos arquivos de saída em vez de sobrescrevê-los."),
        t(Saida, "resume", "--resume", "Retomar scan interrompido", "Continua um scan interrompido a partir do arquivo de saída normal (-oN) ou grepável (-oG). As demais opções vêm do arquivo.").ph("scan.txt"),
        b(Saida, "noninteractive", "--noninteractive", "Desligar teclas durante o scan", "Por padrão, teclas como v, d e p alteram o nível de detalhe durante o scan. Esta opção desliga isso (útil em scripts e agendamentos)."),
        t(Saida, "stylesheet", "--stylesheet", "Folha de estilo (XSL)", "Define o XSL usado para transformar o XML em HTML ao abrir no navegador.").ph("nmap.xsl"),
        b(Saida, "webxml", "--webxml", "Usar estilo do nmap.org", "Referencia a folha de estilo do site do nmap, para o XML abrir bonito em qualquer computador."),
        b(Saida, "nostylesheet", "--no-stylesheet", "Sem folha de estilo", "Não associa nenhuma folha de estilo ao XML."),
        tm(Saida, "statsevery", "--stats-every", "Relatório de progresso periódico", "Imprime o andamento do scan neste intervalo. O nscope já usa 1s por conta própria quando você não define.").ph("10s"),
        b(Saida, "logerrors", "--log-errors", "Registrar erros no arquivo", "Grava erros e avisos também nos arquivos de saída normal."),

        // ---------- AVANÇADO ----------
        b(Avancado, "six", "-6", "Escanear IPv6", "Ativa o suporte a IPv6. Os alvos devem ser endereços IPv6 ou nomes com registro AAAA."),
        t(Avancado, "datadir", "--datadir", "Pasta de dados do nmap", "Usa uma pasta personalizada para os arquivos de dados (bases de serviços, de SO e scripts).").ph("/opt/nmap/data"),
        c(Avancado, "sendmode", "Camada de envio", "Força como o nmap envia os pacotes.", vec![
            ch("auto", "Automático", "", "O nmap escolhe a melhor opção."),
            ch("eth", "Quadros Ethernet (--send-eth)", "--send-eth", "Envia na camada 2 (Ethernet), em vez de pela camada IP.").hard(),
            ch("ip", "Pacotes IP (--send-ip)", "--send-ip", "Envia na camada 3 (IP), em vez de quadros Ethernet.").hard(),
        ]),
        c(Avancado, "privmode", "Modo de privilégios", "Diz ao nmap (e ao nscope) como tratar os privilégios, ignorando a detecção automática. Útil quando o nmap tem capabilities no Linux.", vec![
            ch("auto", "Detectar sozinho", "", "O nmap verifica se você pode usar sockets brutos."),
            ch("priv", "Assumir administrador (--privileged)", "--privileged", "Assume que você tem todos os privilégios (útil em sistemas com capabilities)."),
            ch("unpriv", "Assumir usuário comum (--unprivileged)", "--unprivileged", "Assume que você não tem privilégios de sockets brutos."),
        ]),
        b(Avancado, "V", "-V", "Mostrar a versão do nmap", "Imprime a versão e sai.").standalone(),
        b(Avancado, "h", "-h", "Mostrar a ajuda do nmap", "Imprime o resumo de opções e sai.").standalone(),
        t(Avancado, "extra", "", "Flags extras (campo livre)", "Qualquer opção que não aparece nas listas, escrita como no terminal. É a válvula de escape para cobrir 100% do nmap. Nunca passa por shell.")
            .fmt(Fmt::Raw).ph("--nsock-engine epoll").when("Opções novas ou raras de versões recentes do nmap.")
            .caution("Não aceita ; & | \\ $ < > ( ) ` (não há shell aqui) nem flags de saída (-oN/-oX/-oG/-oS/-oA) e --stats-every: use a aba Saída."),
    ]
}

static CATALOG: OnceLock<Vec<Opt>> = OnceLock::new();
static INDEX: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();

pub fn all() -> &'static [Opt] {
    CATALOG.get_or_init(build)
}

pub fn get(id: &str) -> Option<&'static Opt> {
    let idx = INDEX.get_or_init(|| all().iter().enumerate().map(|(i, o)| (o.id, i)).collect());
    idx.get(id).map(|&i| &all()[i])
}

pub fn section(s: Section) -> impl Iterator<Item = &'static Opt> {
    all().iter().filter(move |o| o.section == s)
}

/// Valores atuais de todas as opções (texto; bool = "1" ligado; escolha = id).
#[derive(Clone, Debug, PartialEq)]
pub struct Values(HashMap<&'static str, String>);

impl Default for Values {
    fn default() -> Self {
        Values(
            all()
                .iter()
                .map(|o| (o.id, o.default_value().to_string()))
                .collect(),
        )
    }
}

impl Values {
    pub fn get(&self, id: &str) -> &str {
        self.0.get(id).map(String::as_str).unwrap_or("")
    }
    pub fn set(&mut self, id: &str, v: impl Into<String>) {
        if let Some(o) = get(id) {
            self.0.insert(o.id, v.into());
        }
    }
    pub fn reset(&mut self, id: &str) {
        if let Some(o) = get(id) {
            self.0.insert(o.id, o.default_value().to_string());
        }
    }
    /// Atalho para `get(id) == "1"` (opções booleanas).
    pub fn flag(&self, id: &str) -> bool {
        self.get(id) == "1"
    }
    /// Texto aparado de uma opção de texto/número.
    pub fn text(&self, id: &str) -> &str {
        self.get(id).trim()
    }
    pub fn visible(&self, o: &Opt) -> bool {
        o.visible_if.is_none_or(|c| self.get(c.id) == c.is)
    }
    /// A opção está "ligada" (altera o comando)? Ignora visibilidade.
    pub fn is_set(&self, o: &Opt) -> bool {
        match o.kind {
            Kind::Bool => self.flag(o.id),
            Kind::Choice => self.get(o.id) != o.default_value(),
            _ => !self.text(o.id).is_empty(),
        }
    }
    /// Visível e ligada.
    pub fn on(&self, id: &str) -> bool {
        get(id).is_some_and(|o| self.visible(o) && self.is_set(o))
    }
    pub fn modified(&self, o: &Opt) -> bool {
        self.get(o.id) != o.default_value()
    }
    /// Quantas opções (que emitem algo) estão ativas na seção.
    pub fn active_count(&self, s: Section) -> usize {
        section(s)
            .filter(|o| !o.helper && self.visible(o) && self.is_set(o))
            .count()
    }
    /// Nível de privilégio exigido pelo valor atual da opção.
    pub fn root_of(&self, o: &Opt) -> Root {
        if o.kind == Kind::Choice {
            o.choice(self.get(o.id)).map_or(Root::None, |c| c.root)
        } else {
            o.root
        }
    }
    /// Flag efetivamente emitida (para mensagens).
    pub fn flag_of(&self, o: &Opt) -> &'static str {
        if o.kind == Kind::Choice {
            o.choice(self.get(o.id)).map_or("", |c| c.flag)
        } else {
            o.flag
        }
    }
}

fn md(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Referência `flag → explicação` gerada do próprio catálogo (docs/CATALOGO.md).
pub fn to_markdown() -> String {
    let mut o = String::from(
        "# Catálogo de opções\n\n> Gerado a partir de `src/nmap/catalog.rs` (`nscope --print-catalog`). Não edite à mão.\n",
    );
    for sec in Section::EMIT_ORDER {
        o.push_str(&format!(
            "\n## {}\n\n| Flag | Opção | O que faz | Admin |\n|---|---|---|---|\n",
            sec.title()
        ));
        for opt in section(sec) {
            let root = |r: Root| match r {
                Root::None => "",
                Root::Soft => "melhor com",
                Root::Hard => "exige",
            };
            let flag = if opt.flag.is_empty() {
                "—".to_string()
            } else {
                format!("`{}`", opt.flag)
            };
            o.push_str(&format!(
                "| {flag} | {} | {} | {} |\n",
                md(opt.label),
                md(opt.what),
                root(opt.root)
            ));
            for c in &opt.choices {
                let f = if c.flag.is_empty() {
                    "(padrão)".to_string()
                } else {
                    format!("`{}`", c.flag)
                };
                o.push_str(&format!(
                    "| ↳ {f} | {} | {} | {} |\n",
                    md(c.label),
                    md(c.what),
                    root(c.root)
                ));
            }
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_unicos_e_defaults_validos() {
        let mut seen = std::collections::HashSet::new();
        for o in all() {
            assert!(seen.insert(o.id), "id repetido: {}", o.id);
            assert!(
                !o.label.is_empty() && !o.what.is_empty(),
                "{} sem texto",
                o.id
            );
            if o.kind == Kind::Choice {
                assert!(!o.choices.is_empty());
                assert!(
                    o.choices[0].flag.is_empty(),
                    "{}: padrão não pode emitir flag",
                    o.id
                );
            }
            if let Some(c) = o.visible_if {
                assert!(
                    get(c.id).is_some_and(|d| d.kind == Kind::Choice && d.choice(c.is).is_some()),
                    "{}: condição inválida",
                    o.id
                );
            }
            for ch in &o.choices {
                if let Some(a) = ch.arg_from {
                    assert!(
                        get(a).is_some_and(|x| x.helper),
                        "{}: arg_from inválido",
                        o.id
                    );
                }
            }
        }
    }

    #[test]
    fn todas_as_flags_da_especificacao_existem() {
        let flags = [
            "-iL",
            "-iR",
            "--exclude",
            "--excludefile",
            "-Pn",
            "-PS",
            "-PA",
            "-PU",
            "-PY",
            "-PE",
            "-PP",
            "-PM",
            "-PO",
            "--dns-servers",
            "--system-dns",
            "--traceroute",
            "-sU",
            "--scanflags",
            "--exclude-ports",
            "-r",
            "-sV",
            "--version-intensity",
            "--version-light",
            "--version-all",
            "--version-trace",
            "-O",
            "--osscan-limit",
            "--osscan-guess",
            "-A",
            "-sC",
            "--script",
            "--script-args",
            "--script-args-file",
            "--script-trace",
            "--script-updatedb",
            "--script-help",
            "--min-hostgroup",
            "--max-hostgroup",
            "--min-parallelism",
            "--max-parallelism",
            "--min-rtt-timeout",
            "--max-rtt-timeout",
            "--initial-rtt-timeout",
            "--max-retries",
            "--host-timeout",
            "--scan-delay",
            "--max-scan-delay",
            "--min-rate",
            "--max-rate",
            "--defeat-rst-ratelimit",
            "--defeat-icmp-ratelimit",
            "-f",
            "--mtu",
            "-D",
            "-S",
            "-e",
            "-g",
            "--proxies",
            "--data",
            "--data-string",
            "--data-length",
            "--ip-options",
            "--ttl",
            "--spoof-mac",
            "--badsum",
            "-oN",
            "-oX",
            "-oG",
            "-oS",
            "-oA",
            "--reason",
            "--open",
            "--packet-trace",
            "--iflist",
            "--append-output",
            "--resume",
            "--noninteractive",
            "--stylesheet",
            "--webxml",
            "--no-stylesheet",
            "--stats-every",
            "--log-errors",
            "-6",
            "--datadir",
            "-V",
            "-h",
        ];
        let mut have: Vec<&str> = all().iter().map(|o| o.flag).collect();
        for o in all() {
            have.extend(o.choices.iter().map(|c| c.flag));
        }
        for f in flags {
            assert!(have.contains(&f), "faltando {f}");
        }
        for f in [
            "-sL",
            "-sn",
            "-sS",
            "-sT",
            "-sA",
            "-sW",
            "-sM",
            "-sN",
            "-sF",
            "-sX",
            "-sY",
            "-sZ",
            "-sO",
            "-sI",
            "-b",
            "-F",
            "-p-",
            "-p",
            "--top-ports",
            "--port-ratio",
            "-T0",
            "-T5",
            "-n",
            "-R",
            "-v",
            "-vvv",
            "-d",
            "-ddd",
            "--send-eth",
            "--send-ip",
            "--privileged",
            "--unprivileged",
        ] {
            assert!(have.contains(&f), "faltando {f}");
        }
    }

    #[test]
    fn catalogo_em_docs_esta_atualizado() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/CATALOGO.md");
        let now = to_markdown();
        if std::env::var_os("UPDATE_CATALOG").is_some() {
            std::fs::write(&path, &now).unwrap();
        }
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            old, now,
            "docs/CATALOGO.md desatualizado: rode UPDATE_CATALOG=1 cargo test catalogo"
        );
    }
}
