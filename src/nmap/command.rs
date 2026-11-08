//! Monta os tokens do comando (com explicação e cor) a partir dos valores do catálogo.
//! O comando é sempre uma lista de argumentos: nada aqui passa por shell.

use super::catalog::{self, Fmt, Kind, Opt, Section, Values};
use super::validate;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Program,
    Flag,
    Value,
    Target,
    Plain,
}

#[derive(Clone, Debug)]
pub struct Token {
    /// Opção de origem (id do catálogo).
    pub opt: &'static str,
    /// Argumentos reais enviados ao nmap (sem passar por shell).
    pub argv: Vec<String>,
    /// Como o token aparece no comando exibido, em pedaços coloridos.
    pub parts: Vec<(String, Class)>,
    pub explain: String,
    /// O valor ainda não foi preenchido (ex.: `-sI <host zumbi>`): não pode ser executado.
    pub placeholder: bool,
}

impl Token {
    pub fn display(&self) -> String {
        self.parts.iter().map(|(s, _)| s.as_str()).collect()
    }
    /// Primeiro pedaço que é flag (para a tabela de explicações).
    pub fn is_target(&self) -> bool {
        self.parts.first().is_some_and(|(_, c)| *c == Class::Target)
    }
}

/// Aspas simples quando há caracteres fora de [A-Za-z0-9_@%+=:,./-] (inclusive `*`, contra glob ao copiar).
pub fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn tok(
    o: &Opt,
    argv: Vec<String>,
    parts: Vec<(String, Class)>,
    explain: &str,
    placeholder: bool,
) -> Token {
    Token {
        opt: o.id,
        argv,
        parts,
        explain: explain.to_string(),
        placeholder,
    }
}

fn emit(v: &Values, o: &'static Opt, out: &mut Vec<Token>) {
    if o.helper || !v.visible(o) {
        return;
    }
    let f = |s: &str| (s.to_string(), Class::Flag);
    let val = |s: &str| (s.to_string(), Class::Value);
    match o.kind {
        Kind::Bool => {
            if v.flag(o.id) {
                out.push(tok(o, vec![o.flag.into()], vec![f(o.flag)], o.what, false));
            }
        }
        Kind::Choice => {
            let Some(c) = o.choice(v.get(o.id)) else {
                return;
            };
            if c.flag.is_empty() {
                return;
            }
            match c.arg_from {
                None => out.push(tok(o, vec![c.flag.into()], vec![f(c.flag)], c.what, false)),
                Some(a) => {
                    let raw = v.text(a);
                    let missing = raw.is_empty();
                    let shown = if missing {
                        format!(
                            "<{}>",
                            catalog::get(a).map_or("valor", |h| h.label).to_lowercase()
                        )
                    } else {
                        quote(raw)
                    };
                    out.push(tok(
                        o,
                        vec![c.flag.into(), raw.into()],
                        vec![f(c.flag), (" ".into(), Class::Plain), val(&shown)],
                        c.what,
                        missing,
                    ));
                }
            }
        }
        Kind::Text | Kind::Number => {
            let s = v.text(o.id);
            if s.is_empty() {
                return;
            }
            match o.fmt {
                Fmt::Sep => out.push(tok(
                    o,
                    vec![o.flag.into(), s.into()],
                    vec![f(o.flag), (" ".into(), Class::Plain), val(&quote(s))],
                    o.what,
                    false,
                )),
                Fmt::Cat => out.push(tok(
                    o,
                    vec![format!("{}{s}", o.flag)],
                    vec![f(o.flag), val(&quote(s))],
                    o.what,
                    false,
                )),
                Fmt::Eq => out.push(tok(
                    o,
                    vec![format!("{}={s}", o.flag)],
                    vec![f(o.flag), ("=".into(), Class::Plain), val(&quote(s))],
                    o.what,
                    false,
                )),
                Fmt::Positional => {
                    for t in validate::split_targets(s) {
                        out.push(tok(
                            o,
                            vec![t.into()],
                            vec![(quote(t), Class::Target)],
                            "Alvo: o endereço, nome ou rede que será examinado.",
                            false,
                        ));
                    }
                }
                Fmt::Raw => {
                    for t in validate::extra_args(s).unwrap_or_default() {
                        let class = if t.starts_with('-') {
                            Class::Flag
                        } else {
                            Class::Value
                        };
                        out.push(tok(
                            o,
                            vec![t.clone()],
                            vec![(quote(&t), class)],
                            "Flag extra digitada por você no campo livre.",
                            false,
                        ));
                    }
                }
            }
        }
    }
}

/// Todos os tokens, na ordem de emissão: técnica → descoberta → portas → serviços/SO → scripts →
/// tempo → evasão → saída → avançado → opções de alvo (-iL, -iR, excludes) → alvos posicionais.
pub fn build(v: &Values) -> Vec<Token> {
    let mut out = Vec::new();
    for sec in Section::EMIT_ORDER {
        for o in catalog::section(sec).filter(|o| o.fmt != Fmt::Positional) {
            emit(v, o, &mut out);
        }
    }
    if let Some(o) = catalog::get("targets") {
        emit(v, o, &mut out);
    }
    out
}

/// Comando exibido/copiado: `nmap ...` com aspas simples quando necessário.
pub fn display(tokens: &[Token]) -> String {
    std::iter::once("nmap".to_string())
        .chain(tokens.iter().map(Token::display))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Argumentos para `Command::args` (sem o programa). `None` se há valor obrigatório faltando.
pub fn argv(tokens: &[Token]) -> Option<Vec<String>> {
    if tokens.iter().any(|t| t.placeholder) {
        return None;
    }
    Some(tokens.iter().flat_map(|t| t.argv.iter().cloned()).collect())
}

/// Parágrafo em português simples descrevendo o scan.
pub fn describe(v: &Values) -> String {
    if catalog::all().iter().any(|o| o.standalone && v.on(o.id)) {
        return "Este comando só mostra informações do nmap e sai, sem escanear nada.".into();
    }
    let mut p: Vec<String> = Vec::new();
    let tg = if !v.text("targets").is_empty() {
        v.text("targets").to_string()
    } else if !v.text("iL").is_empty() {
        format!("os alvos do arquivo {}", v.text("iL"))
    } else if !v.text("iR").is_empty() {
        format!("{} alvos aleatórios", v.text("iR"))
    } else {
        "nenhum alvo ainda".into()
    };
    let tec = v.get("tec");
    let how = match tec {
        "sL" => "apenas listando os alvos, sem enviar pacotes a eles",
        "sn" => "só descobrindo quais estão ligados, sem olhar portas",
        "sS" => "enviando pacotes SYN (scan \"meio-aberto\")",
        "sT" => "abrindo conexões TCP completas",
        "sA" => "com pacotes ACK para mapear regras de firewall",
        "sW" => "com o scan TCP Window",
        "sM" => "com o scan TCP Maimon",
        "sN" => "com pacotes TCP sem flags (Null)",
        "sF" => "com pacotes TCP FIN",
        "sX" => "com pacotes TCP Xmas",
        "sY" => "com SCTP INIT",
        "sZ" => "com SCTP COOKIE-ECHO",
        "sO" => "descobrindo quais protocolos IP o alvo aceita",
        "sI" => "por um host zumbi (idle scan)",
        "b" => "por um servidor FTP intermediário (bounce)",
        _ => "usando a técnica padrão (SYN com administrador, conexão completa sem)",
    };
    p.push(format!("Vai examinar {tg}, {how}."));
    if tec != "sL" && tec != "sn" {
        let ports = match v.get("pmode") {
            "F" => "as 100 portas mais comuns".to_string(),
            "all" => "todas as 65535 portas".to_string(),
            "lista" => format!("as portas {}", v.text("plist")),
            "top" => format!("as {} portas mais comuns", v.text("topn")),
            "ratio" => format!("as portas mais frequentes (razão {})", v.text("ratio")),
            _ => "as 1000 portas mais comuns".to_string(),
        };
        let udp = if v.flag("sU") {
            if tec == "auto" {
                ", somente em UDP"
            } else {
                ", em TCP e também em UDP"
            }
        } else {
            ""
        };
        p.push(format!("Testa {ports}{udp}."));
        let a = v.flag("A");
        let mut ex: Vec<String> = Vec::new();
        if v.flag("sV") || a {
            ex.push("identifica o serviço e a versão de cada porta aberta".into());
        }
        if v.flag("O") || a {
            ex.push("tenta descobrir o sistema operacional".into());
        }
        if v.flag("sC") || a {
            ex.push("roda os scripts padrão".into());
        }
        if !v.text("script").is_empty() {
            ex.push(format!("roda os scripts {}", v.text("script")));
        }
        if v.flag("traceroute") || a {
            ex.push("mapeia a rota até o alvo".into());
        }
        if !ex.is_empty() {
            let s = ex.join("; ");
            let mut cs = s.chars();
            p.push(format!(
                "{}{}.",
                cs.next()
                    .map(|c| c.to_uppercase().to_string())
                    .unwrap_or_default(),
                cs.as_str()
            ));
        }
    }
    if v.flag("Pn") {
        p.push("Não testa se os hosts estão ligados antes: assume que todos estão.".into());
    }
    match v.get("T") {
        "T0" => p.push("Velocidade paranoica (muito lenta).".into()),
        "T1" => p.push("Velocidade furtiva (muito lenta).".into()),
        "T2" => p.push("Velocidade educada (mais lenta).".into()),
        "T4" => p.push("Velocidade agressiva.".into()),
        "T5" => p.push("Velocidade insana.".into()),
        _ => {}
    }
    if v.flag("f") || !v.text("mtu").is_empty() {
        p.push("Fragmenta os pacotes.".into());
    }
    if !v.text("D").is_empty() {
        p.push("Mistura iscas ao tráfego.".into());
    }
    let mut out: Vec<String> = ["oN", "oX", "oG", "oS"]
        .iter()
        .filter(|i| !v.text(i).is_empty())
        .map(|i| format!("{} {}", catalog::get(i).map_or("", |o| o.flag), v.text(i)))
        .collect();
    if !v.text("oA").is_empty() {
        out.insert(0, format!("-oA {}", v.text("oA")));
    }
    if !out.is_empty() {
        p.push(format!("Salva o resultado em: {}.", out.join(", ")));
    }
    p.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(sets: &[(&str, &str)]) -> String {
        let mut v = Values::default();
        for (k, x) in sets {
            v.set(k, *x);
        }
        display(&build(&v))
    }

    #[test]
    fn padrao_so_tem_o_alvo() {
        assert_eq!(cmd(&[]), "nmap scanme.nmap.org");
    }

    #[test]
    fn cada_formato() {
        assert_eq!(cmd(&[("g", "53")]), "nmap -g 53 scanme.nmap.org");
        assert_eq!(cmd(&[("PS", "22,80")]), "nmap -PS22,80 scanme.nmap.org");
        assert_eq!(
            cmd(&[("script", "http-title")]),
            "nmap --script=http-title scanme.nmap.org"
        );
        assert_eq!(
            cmd(&[("script", "not intrusive")]),
            "nmap --script='not intrusive' scanme.nmap.org"
        );
        assert_eq!(cmd(&[("sV", "1")]), "nmap -sV scanme.nmap.org");
    }

    #[test]
    fn ordem_de_emissao() {
        let c = cmd(&[
            ("oA", "r"),
            ("T", "T4"),
            ("sV", "1"),
            ("tec", "sS"),
            ("Pn", "1"),
            ("pmode", "F"),
            ("iL", "a.txt"),
            ("six", "1"),
            ("script", "vuln"),
            ("f", "1"),
            ("extra", "--open"),
            ("exclude", "10.0.0.1"),
        ]);
        assert_eq!(
            c,
            "nmap -sS -Pn -F -sV --script=vuln -T4 -f -oA r -6 --open -iL a.txt --exclude 10.0.0.1 scanme.nmap.org"
        );
    }

    #[test]
    fn escolhas_com_argumento() {
        assert_eq!(
            cmd(&[("tec", "sI"), ("zombie", "192.0.2.50:80")]),
            "nmap -sI 192.0.2.50:80 scanme.nmap.org"
        );
        assert_eq!(
            cmd(&[("pmode", "lista"), ("plist", "T:80,U:53")]),
            "nmap -p T:80,U:53 scanme.nmap.org"
        );
        assert_eq!(
            cmd(&[("pmode", "top"), ("topn", "50")]),
            "nmap --top-ports 50 scanme.nmap.org"
        );
        assert_eq!(
            cmd(&[("pmode", "ratio"), ("ratio", "0.3")]),
            "nmap --port-ratio 0.3 scanme.nmap.org"
        );
        assert_eq!(cmd(&[("pmode", "all")]), "nmap -p- scanme.nmap.org");
        assert_eq!(
            cmd(&[
                ("sendmode", "eth"),
                ("privmode", "unpriv"),
                ("v", "v2"),
                ("d", "d1"),
                ("dns", "n")
            ]),
            "nmap -n -vv -d --send-eth --unprivileged scanme.nmap.org"
        );
    }

    #[test]
    fn campos_auxiliares_so_aparecem_com_a_escolha() {
        // zumbi preenchido mas técnica não é idle: não entra no comando
        assert_eq!(cmd(&[("zombie", "192.0.2.50")]), "nmap scanme.nmap.org");
        assert_eq!(cmd(&[("plist", "22")]), "nmap scanme.nmap.org");
    }

    #[test]
    fn aspas_e_globs() {
        assert_eq!(
            cmd(&[("targets", "192.168.0.* a.com")]),
            "nmap '192.168.0.*' a.com"
        );
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a_b@c%d+e=f:g,h./-"), "a_b@c%d+e=f:g,h./-");
        assert_eq!(quote("a;b"), "'a;b'");
    }

    #[test]
    fn argv_nao_usa_shell_e_separa_argumentos() {
        let mut v = Values::default();
        v.set("scriptargs", "a=b c");
        v.set("g", "53");
        v.set("extra", "--nsock-engine epoll");
        v.set("targets", "10.0.0.*");
        let a = argv(&build(&v)).unwrap();
        assert_eq!(
            a,
            [
                "--script-args=a=b c",
                "-g",
                "53",
                "--nsock-engine",
                "epoll",
                "10.0.0.*"
            ]
        );
    }

    #[test]
    fn valor_faltando_bloqueia_argv() {
        let mut v = Values::default();
        v.set("tec", "b");
        let t = build(&v);
        assert!(display(&t).contains("-b <servidor ftp relay>"));
        assert!(argv(&t).is_none());
    }

    #[test]
    fn extras_invalidos_nao_emitem() {
        let mut v = Values::default();
        v.set("extra", "-sS; rm -rf /");
        assert_eq!(display(&build(&v)), "nmap scanme.nmap.org");
    }

    #[test]
    fn explicacoes_e_classes() {
        let mut v = Values::default();
        v.set("sV", "1");
        let t = build(&v);
        assert!(t[0].explain.contains("serviço"));
        assert_eq!(t[0].parts[0].1, Class::Flag);
        assert!(t.last().unwrap().is_target());
    }

    #[test]
    fn descricao_em_palavras_simples() {
        let mut v = Values::default();
        v.set("sV", "1");
        v.set("oA", "rel");
        let d = describe(&v);
        assert!(d.starts_with("Vai examinar scanme.nmap.org"), "{d}");
        assert!(
            d.contains("1000 portas") && d.contains("versão") && d.contains("-oA rel"),
            "{d}"
        );
        v.set("V", "1");
        assert!(describe(&v).contains("só mostra informações"));
    }

    #[test]
    fn cada_opcao_do_catalogo_emite_exatamente_a_sua_flag() {
        use crate::nmap::catalog::{Kind, all};
        for o in all()
            .iter()
            .filter(|o| o.fmt != Fmt::Positional && o.fmt != Fmt::Raw)
        {
            let mut v = Values::default();
            v.set("targets", "192.0.2.1");
            match o.kind {
                Kind::Bool => {
                    v.set(o.id, "1");
                    let t = build(&v);
                    let hit: Vec<_> = t.iter().filter(|k| k.opt == o.id).collect();
                    assert_eq!(hit.len(), 1, "{}", o.id);
                    assert_eq!(hit[0].argv, [o.flag], "{}", o.id);
                }
                Kind::Choice => {
                    for c in o.choices.iter().skip(1) {
                        let mut v = v.clone();
                        v.set(o.id, c.id);
                        if let Some(a) = c.arg_from {
                            v.set(a, catalog::get(a).unwrap().placeholder);
                        }
                        let t = build(&v);
                        let hit = t
                            .iter()
                            .find(|k| k.opt == o.id)
                            .unwrap_or_else(|| panic!("{}={}", o.id, c.id));
                        assert_eq!(hit.argv[0], c.flag, "{}={}", o.id, c.id);
                        assert!(!hit.placeholder);
                    }
                }
                Kind::Text | Kind::Number if !o.helper => {
                    v.set(o.id, o.placeholder);
                    assert!(
                        validate::value(&o.validator, o.placeholder).is_ok(),
                        "{}: exemplo inválido",
                        o.id
                    );
                    let t = build(&v);
                    let hit = t
                        .iter()
                        .find(|k| k.opt == o.id)
                        .unwrap_or_else(|| panic!("{}", o.id));
                    let expect: Vec<String> = match o.fmt {
                        Fmt::Cat => vec![format!("{}{}", o.flag, o.placeholder)],
                        Fmt::Eq => vec![format!("{}={}", o.flag, o.placeholder)],
                        _ => vec![o.flag.to_string(), o.placeholder.to_string()],
                    };
                    assert_eq!(hit.argv, expect, "{}", o.id);
                }
                _ => {}
            }
        }
    }
}
