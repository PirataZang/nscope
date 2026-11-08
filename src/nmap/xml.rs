//! Leitor do XML do nmap (`-oX`) para structs. Tolera campos ausentes; nunca entra em pânico.
//! Todo texto vindo do XML é sanitizado aqui, na entrada (ver `util::clean`).

use crate::util::{clean, clean_multiline};
use roxmltree::{Document, Node, ParsingOptions};
use std::io::Read;
use std::path::Path;

pub const MAX_XML_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_HOSTS: usize = 5000;
pub const MAX_PORTS_PER_HOST: usize = 3000;
const MAX_FIELD: usize = 1024;
const MAX_SCRIPT_OUT: usize = 16 * 1024;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Script {
    pub id: String,
    pub output: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Port {
    pub protocol: String,
    pub number: u16,
    pub state: String,
    pub reason: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub extra: String,
    pub tunnel: String,
    pub scripts: Vec<Script>,
}

impl Port {
    /// "nginx 1.18.0 (Ubuntu)": produto, versão e informação extra juntos.
    pub fn version_text(&self) -> String {
        [
            self.product.as_str(),
            self.version.as_str(),
            if self.extra.is_empty() {
                ""
            } else {
                &self.extra
            },
        ]
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.is_empty())
        .map(|(i, s)| {
            if i == 2 {
                format!("({s})")
            } else {
                s.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
    }
    pub fn is_open(&self) -> bool {
        self.state == "open" || self.state == "open|filtered"
    }
}

/// Portas não exibidas ("extraports").
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Hidden {
    pub state: String,
    pub count: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Hop {
    pub ttl: String,
    pub rtt: String,
    pub address: String,
    pub host: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OsGuess {
    pub name: String,
    pub accuracy: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Host {
    pub address: String,
    pub hostname: String,
    pub mac: String,
    pub state: String,
    pub os: Option<OsGuess>,
    pub ports: Vec<Port>,
    pub hidden: Vec<Hidden>,
    pub hops: Vec<Hop>,
    pub scripts: Vec<Script>,
}

impl Host {
    pub fn open_count(&self) -> usize {
        self.ports.iter().filter(|p| p.state == "open").count()
    }
    pub fn is_up(&self) -> bool {
        self.state == "up"
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanResult {
    pub command: String,
    pub started: String,
    pub duration_secs: Option<f64>,
    pub summary: String,
    pub hosts_up: u32,
    pub hosts_down: u32,
    pub hosts_total: u32,
    pub hosts: Vec<Host>,
    /// Avisos do próprio leitor (ex.: limites de exibição atingidos).
    pub warnings: Vec<String>,
}

fn limited(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        s.chars().take(max).collect::<String>() + "…"
    } else {
        s.to_string()
    }
}
fn attr(n: Node, name: &str) -> String {
    n.attribute(name)
        .map(|v| limited(&clean(v), MAX_FIELD))
        .unwrap_or_default()
}
fn num<T: std::str::FromStr + Default>(n: Node, name: &str) -> T {
    n.attribute(name)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_default()
}
fn kids<'a, 'b>(n: Node<'a, 'b>, tag: &'static str) -> impl Iterator<Item = Node<'a, 'b>> {
    n.children().filter(move |c| c.has_tag_name(tag))
}
fn scripts(n: Node) -> Vec<Script> {
    kids(n, "script")
        .map(|s| Script {
            id: attr(s, "id"),
            output: limited(
                &clean_multiline(s.attribute("output").unwrap_or("")),
                MAX_SCRIPT_OUT,
            ),
        })
        .collect()
}

fn parse_port(p: Node) -> Option<Port> {
    let number = p.attribute("portid")?.trim().parse::<u16>().ok()?;
    let st = kids(p, "state").next();
    let sv = kids(p, "service").next();
    let a = |n: Option<Node>, k: &str| n.map(|n| attr(n, k)).unwrap_or_default();
    Some(Port {
        protocol: attr(p, "protocol"),
        number,
        state: a(st, "state"),
        reason: a(st, "reason"),
        service: a(sv, "name"),
        product: a(sv, "product"),
        version: a(sv, "version"),
        extra: a(sv, "extrainfo"),
        tunnel: a(sv, "tunnel"),
        scripts: scripts(p),
    })
}

fn parse_host(h: Node, warnings: &mut Vec<String>) -> Host {
    let mut host = Host::default();
    if let Some(s) = kids(h, "status").next() {
        host.state = attr(s, "state");
    }
    for a in kids(h, "address") {
        match a.attribute("addrtype") {
            Some("mac") => host.mac = attr(a, "addr"),
            _ if host.address.is_empty() => host.address = attr(a, "addr"),
            _ => {}
        }
    }
    host.hostname = kids(h, "hostnames")
        .flat_map(|hn| kids(hn, "hostname"))
        .map(|n| attr(n, "name"))
        .find(|n| !n.is_empty())
        .unwrap_or_default();
    if let Some(ports) = kids(h, "ports").next() {
        for ex in kids(ports, "extraports") {
            let reason = kids(ex, "extrareasons")
                .map(|r| attr(r, "reason"))
                .find(|r| !r.is_empty())
                .unwrap_or_default();
            host.hidden.push(Hidden {
                state: attr(ex, "state"),
                count: num(ex, "count"),
                reason,
            });
        }
        let all: Vec<Node> = kids(ports, "port").collect();
        if all.len() > MAX_PORTS_PER_HOST {
            warnings.push(format!(
                "{}: só as primeiras {MAX_PORTS_PER_HOST} de {} portas são exibidas.",
                host.address,
                all.len()
            ));
        }
        host.ports = all
            .into_iter()
            .take(MAX_PORTS_PER_HOST)
            .filter_map(parse_port)
            .collect();
    }
    if let Some(m) = kids(h, "os").flat_map(|o| kids(o, "osmatch")).next() {
        host.os = Some(OsGuess {
            name: attr(m, "name"),
            accuracy: attr(m, "accuracy"),
        });
    }
    host.hops = kids(h, "trace")
        .flat_map(|t| kids(t, "hop"))
        .map(|n| Hop {
            ttl: attr(n, "ttl"),
            rtt: attr(n, "rtt"),
            address: attr(n, "ipaddr"),
            host: attr(n, "host"),
        })
        .collect();
    host.scripts = kids(h, "hostscript").flat_map(scripts).collect();
    host
}

/// Lê o texto XML de uma saída do nmap.
pub fn parse(xml: &str) -> Result<ScanResult, String> {
    if xml.len() as u64 > MAX_XML_BYTES {
        return Err("O XML é grande demais (mais de 64 MiB); o nscope não o abre.".into());
    }
    // O nmap emite <!DOCTYPE nmaprun>: DTD permitido; limites de expansão padrão da biblioteca mantidos.
    let opts = ParsingOptions {
        allow_dtd: true,
        ..Default::default()
    };
    let doc = Document::parse_with_options(xml, opts).map_err(|e| {
        format!(
            "O XML não pôde ser lido ({e}). Se o scan foi interrompido, o arquivo fica incompleto."
        )
    })?;
    let root = doc.root_element();
    if !root.has_tag_name("nmaprun") {
        return Err(
            "Este arquivo não parece ser uma saída do nmap (esperava o elemento <nmaprun>).".into(),
        );
    }
    let mut r = ScanResult {
        command: attr(root, "args"),
        started: attr(root, "startstr"),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    let hosts: Vec<Node> = kids(root, "host").collect();
    if hosts.len() > MAX_HOSTS {
        warnings.push(format!(
            "Só os primeiros {MAX_HOSTS} de {} hosts são exibidos.",
            hosts.len()
        ));
    }
    r.hosts = hosts
        .into_iter()
        .take(MAX_HOSTS)
        .map(|h| parse_host(h, &mut warnings))
        .collect();
    if let Some(fin) = kids(root, "runstats")
        .flat_map(|s| kids(s, "finished"))
        .next()
    {
        r.duration_secs = fin.attribute("elapsed").and_then(|v| v.parse().ok());
        r.summary = attr(fin, "summary");
    }
    if let Some(h) = kids(root, "runstats").flat_map(|s| kids(s, "hosts")).next() {
        (r.hosts_up, r.hosts_down, r.hosts_total) = (num(h, "up"), num(h, "down"), num(h, "total"));
    } else {
        r.hosts_up = r.hosts.iter().filter(|h| h.is_up()).count() as u32;
        r.hosts_total = r.hosts.len() as u32;
        r.hosts_down = r.hosts_total - r.hosts_up;
    }
    r.warnings = warnings;
    Ok(r)
}

/// Lê um arquivo XML, recusando os maiores que 64 MiB (sem carregá-los).
pub fn read_file(path: &Path) -> Result<ScanResult, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("Não foi possível abrir {}: {e}.", path.display()))?;
    let len = f
        .metadata()
        .map(|m| m.len())
        .map_err(|e| format!("Não foi possível ler {}: {e}.", path.display()))?;
    if len > MAX_XML_BYTES {
        return Err(format!(
            "{} tem mais de 64 MiB; o nscope não abre arquivos tão grandes.",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    f.take(MAX_XML_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Erro ao ler {}: {e}.", path.display()))?;
    parse(&String::from_utf8_lossy(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASICO: &str = include_str!("../../fixtures/basico.xml");

    #[test]
    fn fixture_basica() {
        let r = parse(BASICO).unwrap();
        assert!(r.command.starts_with("nmap -sV"));
        assert_eq!((r.hosts_up, r.hosts_down, r.hosts_total), (2, 1, 3));
        assert_eq!(r.duration_secs, Some(14.52));
        assert_eq!(r.hosts.len(), 3);
        let h = &r.hosts[0];
        assert_eq!(
            (h.address.as_str(), h.hostname.as_str(), h.state.as_str()),
            ("192.0.2.10", "servidor.exemplo.test", "up")
        );
        assert_eq!(h.mac, "00:00:5E:00:53:01");
        assert_eq!(h.ports.len(), 4);
        assert_eq!(h.open_count(), 2);
        let ssh = &h.ports[0];
        assert_eq!(
            (
                ssh.number,
                ssh.protocol.as_str(),
                ssh.state.as_str(),
                ssh.service.as_str()
            ),
            (22, "tcp", "open", "ssh")
        );
        assert_eq!(
            ssh.version_text(),
            "OpenSSH 8.9p1 (Ubuntu Linux; protocol 2.0)"
        );
        assert_eq!(ssh.scripts[0].id, "ssh-hostkey");
        assert!(ssh.scripts[0].output.contains('\n'));
        assert_eq!(h.ports[2].state, "filtered");
        assert_eq!(h.ports[3].protocol, "udp");
        assert_eq!(h.ports[3].state, "open|filtered");
        assert_eq!(
            h.hidden,
            [Hidden {
                state: "closed".into(),
                count: 995,
                reason: "resets".into()
            }]
        );
        assert_eq!(h.os.as_ref().unwrap().accuracy, "96");
        assert_eq!(h.hops.len(), 2);
        assert_eq!(h.hops[1].host, "servidor.exemplo.test");
        assert_eq!(h.scripts[0].id, "smb-os-discovery");
        assert_eq!(h.ports[1].tunnel, "ssl");
    }

    #[test]
    fn host_caido_e_sem_campos() {
        let r = parse(BASICO).unwrap();
        let down = &r.hosts[2];
        assert!(
            !down.is_up() && down.ports.is_empty() && down.os.is_none() && down.hostname.is_empty()
        );
        let r = parse(r#"<nmaprun><host><address addr="192.0.2.1"/><ports><port portid="80"><state state="open"/></port><port portid="x"/></ports></host></nmaprun>"#).unwrap();
        assert_eq!(r.hosts[0].ports.len(), 1);
        assert_eq!(r.hosts[0].ports[0].service, "");
        assert_eq!(r.hosts_total, 1);
    }

    #[test]
    fn ipv6() {
        let r = parse(include_str!("../../fixtures/ipv6.xml")).unwrap();
        assert_eq!(r.hosts[0].address, "2001:db8::10");
        assert_eq!(r.hosts[0].ports[0].number, 443);
    }

    #[test]
    fn xml_malformado_e_estranho() {
        for bad in [
            "",
            "<nmaprun>",
            "<nmaprun><host></nmaprun>",
            "nao e xml",
            "<outra/>",
            "<nmaprun><host><address addr=\"a\"></nmaprun>",
        ] {
            let e = parse(bad).expect_err(bad);
            assert!(!e.is_empty());
        }
        assert!(parse(include_str!("../../fixtures/malformado.xml")).is_err());
    }

    #[test]
    fn texto_malicioso_e_sanitizado() {
        // ESC cru é inválido em XML 1.0; chegam por aqui os C1 (CSI), DEL, bidi e largura zero
        let x = "<nmaprun><host><status state=\"up\"/><address addr=\"192.0.2.1\"/><hostnames><hostname name=\"a&#x7f;b&#x202E;c\"/></hostnames>\
                 <ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\" product=\"x&#x9b;31my\"/>\
                 <script id=\"banner\" output=\"l1&#10;l2&#x9b;31m&#13;&#x200B;\"/></port></ports></host></nmaprun>";
        let r = parse(x).unwrap();
        let h = &r.hosts[0];
        assert_eq!(h.hostname, "a·b·c");
        assert_eq!(h.ports[0].product, "x·31my");
        assert_eq!(h.ports[0].scripts[0].output, "l1\nl2·31m·");
        let all = format!("{h:?}");
        assert!(!all.contains('\u{9b}') && !all.contains('\u{202e}') && !all.contains('\u{200b}'));
    }

    #[test]
    fn limites_de_exibicao() {
        let mut x = String::from("<nmaprun>");
        for i in 0..(MAX_HOSTS + 3) {
            x.push_str(&format!(
                "<host><status state=\"up\"/><address addr=\"192.0.2.{}\"/></host>",
                i % 250
            ));
        }
        x.push_str("</nmaprun>");
        let r = parse(&x).unwrap();
        assert_eq!(r.hosts.len(), MAX_HOSTS);
        assert!(r.warnings[0].contains("primeiros"));
        let mut y = String::from("<nmaprun><host><address addr=\"192.0.2.1\"/><ports>");
        for p in 1..=(MAX_PORTS_PER_HOST + 5) {
            y.push_str(&format!(
                "<port protocol=\"tcp\" portid=\"{p}\"><state state=\"open\"/></port>"
            ));
        }
        y.push_str("</ports></host></nmaprun>");
        let r = parse(&y).unwrap();
        assert_eq!(r.hosts[0].ports.len(), MAX_PORTS_PER_HOST);
        assert!(!r.warnings.is_empty());
    }

    #[test]
    fn arquivo_gigante_e_recusado_sem_ler() {
        let dir = std::env::temp_dir().join(format!("nscope-xmltest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.xml");
        let f = std::fs::File::create(&big).unwrap();
        f.set_len(MAX_XML_BYTES + 1).unwrap();
        let e = read_file(&big).unwrap_err();
        assert!(e.contains("64 MiB"), "{e}");
        assert!(read_file(&dir.join("nao-existe.xml")).is_err());
        std::fs::write(dir.join("ok.xml"), BASICO).unwrap();
        assert_eq!(read_file(&dir.join("ok.xml")).unwrap().hosts.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn entidades_expansivas_sao_limitadas_pela_biblioteca() {
        // "billion laughs": a roxmltree deve recusar (limite padrão de expansão), nunca estourar a memória
        let x = "<?xml version=\"1.0\"?><!DOCTYPE nmaprun [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">\
                 <!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\"><!ENTITY e \"&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;\"><!ENTITY f \"&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;\">\
                 <!ENTITY g \"&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;\"><!ENTITY h \"&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;\">]><nmaprun args=\"&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;\"/>";
        assert!(parse(x).is_err());
    }
}
