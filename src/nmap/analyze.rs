//! Análise do comando: erros (bloqueiam), avisos e informações, cada um com atalho para a opção.

use super::catalog::{self, Kind, Root, Values};
use super::knowledge::{self, Risk};
use super::validate;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error,
    Warn,
    Info,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub level: Level,
    pub msg: String,
    /// Opção responsável (para o atalho "ir").
    pub opt: Option<&'static str>,
}

pub fn has_errors(f: &[Finding]) -> bool {
    f.iter().any(|x| x.level == Level::Error)
}

// ---------- escopo / autorização ----------

fn ipv4(s: &str) -> Option<u32> {
    let p: Vec<&str> = s.split('.').collect();
    if p.len() != 4 {
        return None;
    }
    let mut n = 0u32;
    for x in p {
        if x.is_empty() || x.len() > 3 || !x.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        n = (n << 8) | x.parse::<u32>().ok().filter(|v| *v <= 255)?;
    }
    Some(n)
}

/// Faixa (mínimo, máximo) de um alvo IPv4: IP, CIDR, `*` e `a-b` por octeto.
fn v4_range(t: &str) -> Option<(u32, u32)> {
    let (addr, mask) = match t.split_once('/') {
        Some((a, m)) => (a, Some(m.parse::<u32>().ok().filter(|m| *m <= 32)?)),
        None => (t, None),
    };
    let octs: Vec<&str> = addr.split('.').collect();
    if octs.len() != 4 {
        return None;
    }
    let (mut lo, mut hi) = (0u32, 0u32);
    for o in octs {
        let (a, b) = if o == "*" {
            (0, 255)
        } else if let Some((a, b)) = o.split_once('-') {
            (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)
        } else {
            let n = o.parse::<u32>().ok()?;
            (n, n)
        };
        if a > b || b > 255 || o.is_empty() {
            return None;
        }
        lo = (lo << 8) | a;
        hi = (hi << 8) | b;
    }
    match mask {
        None => Some((lo, hi)),
        Some(m) => {
            let host = if m >= 32 { 0 } else { u32::MAX >> m };
            Some((lo & !host, hi | host))
        }
    }
}

/// Privadas, loopback, link-local e faixas de documentação.
const SAFE_V4: [(&str, u32); 8] = [
    ("10.0.0.0", 8),
    ("172.16.0.0", 12),
    ("192.168.0.0", 16),
    ("127.0.0.0", 8),
    ("169.254.0.0", 16),
    ("192.0.2.0", 24),
    ("198.51.100.0", 24),
    ("203.0.113.0", 24),
];

fn v4_safe(lo: u32, hi: u32) -> bool {
    SAFE_V4.iter().any(|(a, bits)| {
        let base = ipv4(a).unwrap_or(0);
        let end = base | (u32::MAX >> bits);
        lo >= base && hi <= end
    })
}

fn v6_safe(t: &str) -> bool {
    let t = t.trim_matches(|c| c == '[' || c == ']').to_lowercase();
    let (addr, mask) = match t.split_once('/') {
        Some((a, m)) => (a.to_string(), m.parse::<u32>().unwrap_or(0)),
        None => (t.clone(), 128),
    };
    let addr = addr
        .split('%')
        .next()
        .unwrap_or("")
        .trim_end_matches(']')
        .to_string();
    if addr == "::1" {
        return mask >= 128;
    }
    let first = addr.split(':').next().unwrap_or("");
    if ["fe8", "fe9", "fea", "feb"]
        .iter()
        .any(|p| first.starts_with(p))
        && first.len() == 4
    {
        return mask >= 10;
    }
    if (first.starts_with("fc") || first.starts_with("fd")) && first.len() == 4 {
        return mask >= 7;
    }
    if addr.starts_with("2001:db8:") || addr == "2001:db8::" {
        return mask >= 32;
    }
    false
}

/// O alvo é seguro de escanear sem pedir confirmação (rede privada, loopback, doc, scanme)?
pub fn is_safe_target(t: &str) -> bool {
    let l = t.to_lowercase();
    if l.contains(':') {
        return v6_safe(&l);
    }
    if let Some((lo, hi)) = v4_range(&l) {
        return v4_safe(lo, hi);
    }
    let host = l.split('/').next().unwrap_or("");
    host == "scanme.nmap.org"
        || host == "localhost"
        || [".test", ".localhost", ".example", ".invalid", ".local"]
            .iter()
            .any(|s| host.ends_with(s))
}

/// Alvos que exigem confirmação explícita de autorização antes de executar.
pub fn external_targets(v: &Values) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(list) = validate::targets(v.text("targets")) {
        out.extend(list.into_iter().filter(|t| !is_safe_target(t)));
    }
    if !v.text("iL").is_empty() {
        out.push(format!("(alvos lidos de {})", v.text("iL")));
    }
    if !v.text("iR").is_empty() {
        out.push(format!("({} alvos aleatórios da internet)", v.text("iR")));
    }
    out
}

fn script_items(s: &str) -> Vec<String> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '*'))
        .filter(|x| !x.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Itens de `--script` que são de alto risco (ignora os precedidos de `not`).
fn risky_scripts(s: &str) -> Vec<String> {
    let items = script_items(s);
    let mut out = Vec::new();
    for (i, it) in items.iter().enumerate() {
        let negated = i > 0 && items[i - 1] == "not";
        if !negated && knowledge::script_risk(it) == Some(Risk::High) {
            out.push(it.clone());
        }
    }
    out
}

// ---------- análise ----------

pub fn analyze(v: &Values, privileged: bool) -> Vec<Finding> {
    let mut f: Vec<Finding> = Vec::new();
    let mut add =
        |level: Level, msg: String, opt: Option<&'static str>| f.push(Finding { level, msg, opt });
    let privileged = match v.get("privmode") {
        "priv" => true,
        "unpriv" => false,
        _ => privileged,
    };

    // valores inválidos
    for o in catalog::all().iter().filter(|o| {
        matches!(o.kind, Kind::Text | Kind::Number)
            && v.visible(o)
            && o.id != "targets"
            && o.id != "extra"
    }) {
        if let Err(e) = validate::value(&o.validator, v.get(o.id)) {
            add(Level::Error, format!("{}: {e}", o.label), Some(o.id));
        }
    }
    if v.on("extra")
        && let Err(e) = validate::extra_args(v.get("extra"))
    {
        add(Level::Error, format!("Flags extras: {e}"), Some("extra"));
    }
    if !v.text("targets").is_empty()
        && let Err(e) = validate::targets(v.text("targets"))
    {
        add(Level::Error, e, Some("targets"));
    }

    let stand: Vec<&str> = catalog::all()
        .iter()
        .filter(|o| o.standalone && v.on(o.id))
        .map(|o| o.flag)
        .collect();
    if !stand.is_empty() {
        add(
            Level::Info,
            format!(
                "Estas opções ({}) só mostram informações e saem: nenhum scan será feito.",
                stand.join(", ")
            ),
            None,
        );
        return sorted(f);
    }

    let tec = v.get("tec");
    if v.text("targets").is_empty() && v.text("iL").is_empty() && v.text("iR").is_empty() {
        add(
            Level::Error,
            "Nenhum alvo definido. Preencha \"Alvos\" na aba 1, ou use -iL / -iR.".into(),
            Some("targets"),
        );
    }
    let targets = validate::targets(v.text("targets")).unwrap_or_default();
    let ext: Vec<&String> = targets.iter().filter(|t| !is_safe_target(t)).collect();
    if !ext.is_empty() {
        let l: Vec<&str> = ext.iter().map(|s| s.as_str()).collect();
        add(
            Level::Warn,
            format!(
                "Alvo(s) que não parecem da sua rede ({}): confirme que você tem autorização por escrito antes de escanear.",
                l.join(", ")
            ),
            Some("targets"),
        );
    }
    let big: Vec<&str> = targets
        .iter()
        .filter(|t| {
            !t.contains(':')
                && t.split_once('/')
                    .is_some_and(|(_, m)| m.parse::<u32>().is_ok_and(|m| m < 16))
        })
        .map(|s| s.as_str())
        .collect();
    if !big.is_empty() {
        add(
            Level::Warn,
            format!(
                "Rede muito grande ({}): o scan pode levar horas e gerar muito tráfego.",
                big.join(", ")
            ),
            Some("targets"),
        );
    }
    if v.on("iR") {
        add(
            Level::Warn,
            "Escanear IPs aleatórios da internet gera denúncias de abuso e pode ser ilegal.".into(),
            Some("iR"),
        );
    }
    if v.on("iL") {
        add(Level::Info, "Os alvos do arquivo -iL não são conferidos pelo nscope: garanta que todos estão no seu escopo autorizado.".into(), Some("iL"));
    }
    if tec == "sI" && v.text("zombie").is_empty() {
        add(
            Level::Error,
            "Idle scan precisa de um host zumbi (aba Técnica).".into(),
            Some("zombie"),
        );
    }
    if tec == "b" && v.text("relay").is_empty() {
        add(
            Level::Error,
            "FTP bounce precisa de um servidor FTP relay (aba Técnica).".into(),
            Some("relay"),
        );
    }
    if v.get("pmode") == "lista" && v.text("plist").is_empty() {
        add(
            Level::Error,
            "Informe a lista de portas (aba Portas).".into(),
            Some("plist"),
        );
    }
    if v.get("pmode") == "top" && v.text("topn").is_empty() {
        add(
            Level::Error,
            "Informe quantas portas (--top-ports).".into(),
            Some("topn"),
        );
    }
    if v.get("pmode") == "ratio" && v.text("ratio").is_empty() {
        add(
            Level::Error,
            "Informe a razão de frequência (--port-ratio).".into(),
            Some("ratio"),
        );
    }

    // privilégios
    if !privileged {
        for o in catalog::all()
            .iter()
            .filter(|o| !o.helper && v.visible(o) && v.is_set(o))
        {
            let what = format!("{} ({})", o.label, v.flag_of(o));
            match v.root_of(o) {
                Root::Hard => add(
                    Level::Error,
                    format!(
                        "{what} exige privilégios de administrador. Rode o nscope com sudo (ou, no Windows, como administrador) ou escolha outra opção."
                    ),
                    Some(o.id),
                ),
                Root::Soft => add(
                    Level::Warn,
                    format!(
                        "{what}: sem privilégios o nmap usa uma alternativa ou ignora esta sonda."
                    ),
                    Some(o.id),
                ),
                Root::None => {}
            }
        }
        if tec == "auto" && !v.on("sU") {
            // sem aviso: o automático cai para -sT
        }
    }

    // opções sem efeito
    if tec == "sL" || tec == "sn" {
        let mut ig = Vec::new();
        if v.get("pmode") != "def" {
            ig.push("portas");
        }
        if v.flag("sV") || v.flag("A") {
            ig.push("versão");
        }
        if tec == "sL" {
            if v.flag("O") {
                ig.push("SO");
            }
            if v.flag("sC") || !v.text("script").is_empty() {
                ig.push("scripts");
            }
            if ["Pn", "PS", "PA", "PU", "PY", "PE", "PP", "PM", "PO"]
                .iter()
                .any(|i| v.on(i))
            {
                ig.push("descoberta de hosts");
            }
        }
        if !ig.is_empty() {
            let nome = if tec == "sL" {
                "Só listar alvos"
            } else {
                "Só descobrir hosts"
            };
            add(
                Level::Warn,
                format!(
                    "Com \"{nome}\" as opções de {} não fazem efeito: não há scan de portas.",
                    ig.join(", ")
                ),
                Some("tec"),
            );
        }
        if v.on("sU") {
            add(
                Level::Info,
                "Com este modo não há scan de portas; -sU não terá efeito.".into(),
                Some("sU"),
            );
        }
    }
    if (v.on("osl") || v.on("osg")) && !(v.flag("O") || v.flag("A")) {
        add(
            Level::Warn,
            "--osscan-limit e --osscan-guess só funcionam junto com -O (ou -A).".into(),
            Some(if v.on("osl") { "osl" } else { "osg" }),
        );
    }
    if ["vint", "vlight", "vall", "vtrace"].iter().any(|i| v.on(i))
        && !(v.flag("sV") || v.flag("A"))
    {
        add(
            Level::Warn,
            "As opções de intensidade da versão só funcionam junto com -sV (ou -A).".into(),
            Some("sV"),
        );
    }
    if (v.on("scriptargs") || v.on("scriptargsfile"))
        && !(v.flag("sC") || v.flag("A") || v.on("script"))
    {
        add(
            Level::Warn,
            "Argumentos de scripts sem nenhum script selecionado: serão ignorados.".into(),
            Some("script"),
        );
    }
    if v.flag("Pn") && ["PS", "PA", "PU", "PY", "PO"].iter().any(|i| v.on(i))
        || v.flag("Pn") && ["PE", "PP", "PM"].iter().any(|i| v.flag(i))
    {
        add(Level::Warn, "-Pn desliga a descoberta de hosts; as sondas de ping (-PS, -PA, -PE...) serão ignoradas.".into(), Some("Pn"));
    }
    if v.flag("A") && (v.flag("sV") || v.flag("O") || v.flag("sC") || v.flag("traceroute")) {
        add(
            Level::Info,
            "-A já inclui -sV, -O, -sC e --traceroute; as opções repetidas são redundantes.".into(),
            Some("A"),
        );
    }
    if v.on("scanflags") && ["sL", "sn", "sY", "sZ", "sO", "sI", "b"].contains(&tec) {
        add(
            Level::Warn,
            "--scanflags só tem efeito com técnicas TCP.".into(),
            Some("scanflags"),
        );
    }
    if v.on("proxies") && tec != "sT" {
        add(
            Level::Warn,
            "Proxies só funcionam com conexão completa (-sT).".into(),
            Some("proxies"),
        );
    }
    if v.on("S") && !(v.on("e") && v.flag("Pn")) {
        add(Level::Warn, "Com IP de origem falsificado (-S), as respostas não voltam para você; normalmente é preciso -e <interface> e -Pn.".into(), Some("S"));
    }
    if v.on("D") && !v.text("D").to_uppercase().contains("ME") {
        add(
            Level::Info,
            "Dica: inclua ME na lista de iscas para controlar onde o seu IP real aparece.".into(),
            Some("D"),
        );
    }
    if [
        "f", "mtu", "D", "S", "spoofmac", "badsum", "proxies", "datalen", "ipopts", "g",
    ]
    .iter()
    .any(|i| v.on(i))
    {
        add(Level::Info, "Técnicas de evasão e falsificação são legítimas em testes de intrusão autorizados, e só nesses casos.".into(), Some("f"));
    }
    match v.get("T") {
        "T4" | "T5" => add(Level::Warn, "Velocidades T4 e T5 podem sobrecarregar equipamentos frágeis e perder portas em redes lentas.".into(), Some("T")),
        "T0" | "T1" => add(Level::Info, "T0 e T1 são extremamente lentos: um scan pode levar horas ou dias.".into(), Some("T")),
        _ => {}
    }
    if v.text("minrate").parse::<u64>().is_ok_and(|n| n >= 5000) {
        add(
            Level::Warn,
            "Taxa mínima muito alta: pode saturar a rede e perder resultados.".into(),
            Some("minrate"),
        );
    }
    if v.get("pmode") == "all" && ["T0", "T1", "T2"].contains(&v.get("T")) {
        add(
            Level::Warn,
            "Todas as portas com velocidade baixa vai demorar muito.".into(),
            Some("pmode"),
        );
    }
    if v.flag("sU") && v.get("pmode") == "all" {
        add(
            Level::Warn,
            "UDP em todas as portas é extremamente lento. Considere --top-ports.".into(),
            Some("pmode"),
        );
    }
    let risky = risky_scripts(v.text("script"));
    if !risky.is_empty() {
        add(
            Level::Warn,
            format!(
                "Scripts intrusivos, de força bruta, DoS ou exploração ({}) podem derrubar serviços, bloquear contas e gerar alertas. Só com autorização expressa.",
                risky.join(", ")
            ),
            Some("script"),
        );
    }
    if script_items(v.text("script"))
        .iter()
        .any(|s| s == "external")
    {
        add(
            Level::Info,
            "Scripts da categoria external enviam dados do alvo para serviços de terceiros.".into(),
            Some("script"),
        );
    }
    if v.flag("six") && targets.iter().any(|t| v4_range(t).is_some()) {
        add(
            Level::Warn,
            "-6 espera endereços IPv6 ou nomes com registro AAAA; há um IPv4 nos alvos.".into(),
            Some("six"),
        );
    }
    if v.on("oA") && (v.on("oN") || v.on("oX") || v.on("oG")) {
        add(
            Level::Info,
            "-oA já salva nos três formatos; -oN, -oX e -oG extras são redundantes.".into(),
            Some("oA"),
        );
    }
    if v.on("resume") {
        add(Level::Info, "--resume reaproveita os parâmetros do scan interrompido; as outras opções serão ignoradas.".into(), Some("resume"));
    }
    sorted(f)
}

fn sorted(mut f: Vec<Finding>) -> Vec<Finding> {
    f.sort_by_key(|x| x.level); // estável: mantém a ordem dentro do nível
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(sets: &[(&str, &str)], root: bool) -> Vec<Finding> {
        let mut v = Values::default();
        for (k, x) in sets {
            v.set(k, *x);
        }
        analyze(&v, root)
    }
    fn has(f: &[Finding], lv: Level, needle: &str) -> bool {
        f.iter().any(|x| x.level == lv && x.msg.contains(needle))
    }

    #[test]
    fn padrao_sem_problemas_graves() {
        let f = run(&[], false);
        assert!(!has_errors(&f), "{f:?}");
        assert!(f.iter().all(|x| x.level != Level::Warn), "{f:?}");
    }

    #[test]
    fn erros_bloqueantes() {
        assert!(has(
            &run(&[("targets", "")], false),
            Level::Error,
            "Nenhum alvo"
        ));
        assert!(has(
            &run(&[("targets", "-sS")], false),
            Level::Error,
            "começa com"
        ));
        assert!(has(
            &run(&[("retries", "abc")], false),
            Level::Error,
            "inteiros"
        ));
        assert!(has(
            &run(&[("tec", "sS")], false),
            Level::Error,
            "administrador"
        ));
        assert!(!has_errors(&run(&[("tec", "sS")], true)));
        assert!(has(&run(&[("tec", "sI")], true), Level::Error, "zumbi"));
        assert!(has(&run(&[("tec", "b")], true), Level::Error, "relay"));
        assert!(has(
            &run(&[("pmode", "lista")], false),
            Level::Error,
            "lista de portas"
        ));
        assert!(has(
            &run(&[("pmode", "lista"), ("plist", "80,")], false),
            Level::Error,
            "Lista de portas"
        ));
        assert!(has(
            &run(&[("extra", "a; b")], false),
            Level::Error,
            "Flags extras"
        ));
        assert!(has(&run(&[("mtu", "10")], true), Level::Error, "múltiplo"));
        assert!(has(&run(&[("minrtt", "5x")], false), Level::Error, "tempo"));
        assert!(has(
            &run(&[("data", "ABC")], true),
            Level::Error,
            "hexadecimais"
        ));
    }

    #[test]
    fn privilegios_via_privmode() {
        assert!(!has_errors(&run(
            &[("tec", "sS"), ("privmode", "priv")],
            false
        )));
        assert!(has_errors(&run(
            &[("tec", "sS"), ("privmode", "unpriv")],
            true
        )));
        assert!(has(
            &run(&[("PE", "1")], false),
            Level::Warn,
            "sem privilégios"
        ));
        assert!(!has(
            &run(&[("PE", "1")], true),
            Level::Warn,
            "sem privilégios"
        ));
    }

    #[test]
    fn escopo_e_autorizacao() {
        for s in [
            "192.168.1.10",
            "10.1.2.3",
            "172.16.0.0/12",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.0/24",
            "198.51.100.7",
            "203.0.113.9",
            "scanme.nmap.org",
            "localhost",
            "srv.exemplo.test",
            "192.168.0-3.1",
            "192.168.1.*",
            "::1",
            "fe80::1%eth0",
            "fd12:3456::1",
            "2001:db8::1",
            "[::1]",
        ] {
            assert!(is_safe_target(s), "{s} deveria ser seguro");
        }
        for s in [
            "8.8.8.8",
            "172.32.0.1",
            "10.0.0.0/7",
            "192.168.0.0/15",
            "0.0.0.0/0",
            "example.com",
            "1.1.1.1/32",
            "192.168-170.1.1",
            "2606:4700::1",
            "fe80::/9",
            "evil.test.com",
            "300.1.1.1",
        ] {
            assert!(!is_safe_target(s), "{s} NÃO deveria ser seguro");
        }
        let f = run(&[("targets", "8.8.8.8 192.168.0.1")], false);
        assert!(has(&f, Level::Warn, "8.8.8.8") && !has(&f, Level::Warn, "(8.8.8.8, 192"));
        assert!(has(
            &run(&[("targets", "10.0.0.0/8")], false),
            Level::Warn,
            "muito grande"
        ));
        let mut v = Values::default();
        v.set("targets", "8.8.8.8 10.0.0.1");
        v.set("iL", "x.txt");
        v.set("iR", "5");
        let e = external_targets(&v);
        assert_eq!(e.len(), 3);
        assert!(has(&run(&[("iR", "5")], false), Level::Warn, "aleatórios"));
    }

    #[test]
    fn opcoes_ignoradas() {
        assert!(has(
            &run(&[("tec", "sn"), ("pmode", "F"), ("sV", "1")], false),
            Level::Warn,
            "não fazem efeito"
        ));
        assert!(has(
            &run(&[("tec", "sL"), ("sC", "1")], false),
            Level::Warn,
            "scripts"
        ));
        assert!(has(&run(&[("osg", "1")], false), Level::Warn, "--osscan"));
        assert!(!has(
            &run(&[("osg", "1"), ("A", "1")], true),
            Level::Warn,
            "--osscan"
        ));
        assert!(has(&run(&[("vlight", "1")], false), Level::Warn, "-sV"));
        assert!(has(
            &run(&[("scriptargs", "a=b")], false),
            Level::Warn,
            "Argumentos de scripts"
        ));
        assert!(has(
            &run(&[("Pn", "1"), ("PS", "80")], true),
            Level::Warn,
            "-Pn desliga"
        ));
        assert!(has(
            &run(&[("scanflags", "SYN"), ("tec", "sO")], true),
            Level::Warn,
            "TCP"
        ));
        assert!(has(
            &run(&[("proxies", "socks4://127.0.0.1:9050")], false),
            Level::Warn,
            "-sT"
        ));
        assert!(has(&run(&[("S", "192.0.2.9")], true), Level::Warn, "-S"));
        assert!(!has(
            &run(&[("S", "192.0.2.9"), ("e", "eth0"), ("Pn", "1")], true),
            Level::Warn,
            "falsificado"
        ));
    }

    #[test]
    fn avisos_de_velocidade_e_escopo_de_portas() {
        assert!(has(&run(&[("T", "T4")], false), Level::Warn, "T4"));
        assert!(has(&run(&[("T", "T5")], false), Level::Warn, "T4"));
        assert!(has(
            &run(&[("minrate", "5000")], false),
            Level::Warn,
            "Taxa mínima"
        ));
        assert!(!has(
            &run(&[("minrate", "4999")], false),
            Level::Warn,
            "Taxa mínima"
        ));
        assert!(has(
            &run(&[("pmode", "all"), ("T", "T1")], false),
            Level::Warn,
            "demorar"
        ));
        assert!(has(
            &run(&[("pmode", "all"), ("sU", "1")], true),
            Level::Warn,
            "UDP em todas"
        ));
        assert!(has(
            &run(&[("six", "1"), ("targets", "192.168.0.1")], false),
            Level::Warn,
            "IPv4"
        ));
        assert!(!has(
            &run(&[("six", "1"), ("targets", "2001:db8::1")], false),
            Level::Warn,
            "IPv4"
        ));
    }

    #[test]
    fn scripts_de_risco() {
        for s in [
            "brute",
            "dos,default",
            "exploit",
            "fuzzer",
            "intrusive",
            "ssh-brute",
            "default or brute",
        ] {
            assert!(
                has(&run(&[("script", s)], false), Level::Warn, "força bruta"),
                "{s}"
            );
        }
        assert!(!has(
            &run(&[("script", "not intrusive")], false),
            Level::Warn,
            "força bruta"
        ));
        assert!(!has(
            &run(&[("script", "http-title,safe")], false),
            Level::Warn,
            "força bruta"
        ));
        assert!(has(
            &run(&[("script", "external")], false),
            Level::Info,
            "terceiros"
        ));
    }

    #[test]
    fn informacoes() {
        assert!(has(
            &run(&[("A", "1"), ("sV", "1")], true),
            Level::Info,
            "redundantes"
        ));
        assert!(has(
            &run(&[("oA", "r"), ("oN", "x")], false),
            Level::Info,
            "-oA já salva"
        ));
        assert!(has(
            &run(&[("resume", "x.txt")], false),
            Level::Info,
            "--resume"
        ));
        assert!(has(&run(&[("f", "1")], true), Level::Info, "evasão"));
        assert!(has(&run(&[("D", "1.2.3.4")], true), Level::Info, "ME"));
        assert!(has(
            &run(&[("V", "1")], false),
            Level::Info,
            "só mostram informações"
        ));
        assert!(has(
            &run(&[("sU", "1"), ("tec", "sn")], true),
            Level::Info,
            "-sU"
        ));
    }

    #[test]
    fn ordenado_por_gravidade() {
        let f = run(&[("T", "T4"), ("tec", "sS"), ("f", "1")], false);
        let lv: Vec<Level> = f.iter().map(|x| x.level).collect();
        assert!(lv.windows(2).all(|w| w[0] <= w[1]));
    }
}
