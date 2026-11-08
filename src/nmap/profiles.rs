//! Perfis prontos. Aplicar um perfil mantém os alvos e restaura o resto ao padrão antes.

use super::catalog::Values;

pub struct Profile {
    pub name: &'static str,
    pub short: &'static str,
    pub when: &'static str,
    /// Nível de ruído declarado (0 a 5); um teste confere com a estimativa calculada.
    pub noise: u8,
    pub recommended: bool,
    /// (id da opção, valor). Booleanos usam "1".
    pub set: &'static [(&'static str, &'static str)],
}

const fn pr(
    name: &'static str,
    short: &'static str,
    when: &'static str,
    noise: u8,
    set: &'static [(&'static str, &'static str)],
) -> Profile {
    Profile {
        name,
        short,
        when,
        noise,
        recommended: false,
        set,
    }
}

pub static PROFILES: &[Profile] = &[
    pr(
        "Restaurar padrão",
        "Volta todas as opções ao padrão (mantém os alvos).",
        "Para começar de novo.",
        2,
        &[],
    ),
    pr(
        "Descobrir hosts na rede",
        "Lista as máquinas ligadas, sem olhar portas.",
        "Primeiro passo ao mapear uma rede nova.",
        0,
        &[("tec", "sn")],
    ),
    Profile {
        recommended: true,
        ..pr(
            "Padrão com serviços",
            "As 1000 portas mais comuns, identificando serviço e versão.",
            "O melhor ponto de partida para a maioria dos casos.",
            3,
            &[("sV", "1")],
        )
    },
    pr(
        "Scan rápido",
        "Só as 100 portas mais comuns, em velocidade agressiva.",
        "Rede local confiável, quando você quer uma visão geral em segundos.",
        2,
        &[("pmode", "F"), ("T", "T4")],
    ),
    pr(
        "Todas as portas",
        "As 65535 portas, com versão dos serviços.",
        "Quando precisa achar serviços escondidos em portas incomuns.",
        5,
        &[("pmode", "all"), ("sV", "1"), ("T", "T4")],
    ),
    pr(
        "Auditoria com scripts",
        "Serviços e versão + scripts padrão (banners, certificados, títulos).",
        "Para entender melhor cada serviço encontrado.",
        4,
        &[("sC", "1"), ("sV", "1")],
    ),
    pr(
        "Reconhecimento completo",
        "Modo agressivo (-A): SO, versão, scripts e rota.",
        "Inventário detalhado de um alvo autorizado.",
        5,
        &[("A", "1"), ("T", "T4")],
    ),
    pr(
        "Caça a vulnerabilidades",
        "Versão dos serviços + scripts da categoria vuln.",
        "Auditoria de segurança com autorização. Pode gerar alertas.",
        5,
        &[("sV", "1"), ("script", "vuln")],
    ),
    pr(
        "Discreto para teste autorizado",
        "SYN lento, sem ping, sem DNS e com pacotes fragmentados.",
        "Testes de intrusão em que reduzir a chance de detecção faz parte do escopo.",
        0,
        &[
            ("tec", "sS"),
            ("Pn", "1"),
            ("dns", "n"),
            ("T", "T2"),
            ("f", "1"),
        ],
    ),
    pr(
        "UDP: portas comuns",
        "As 50 portas UDP mais comuns (DNS, SNMP, NTP...).",
        "Para achar serviços que não usam TCP. Demora.",
        2,
        &[("sU", "1"), ("pmode", "top"), ("topn", "50")],
    ),
    pr(
        "Mapear regras de firewall",
        "ACK scan: mostra portas filtradas x não filtradas.",
        "Para entender o que o firewall deixa passar.",
        1,
        &[("tec", "sA"), ("pmode", "F")],
    ),
    pr(
        "Sites e HTTPS",
        "Portas web com título, cabeçalhos, métodos HTTP e certificado.",
        "Inventário de servidores web.",
        3,
        &[
            ("pmode", "lista"),
            ("plist", "80,443,8080,8443"),
            ("sV", "1"),
            ("script", "http-title,http-headers,http-methods,ssl-cert"),
        ],
    ),
    pr(
        "Windows e SMB",
        "Compartilhamento de arquivos, área de trabalho remota e dados do SO.",
        "Redes Windows.",
        3,
        &[
            ("pmode", "lista"),
            ("plist", "139,445,3389"),
            ("sV", "1"),
            ("script", "smb-os-discovery,smb-security-mode,smb-protocols"),
        ],
    ),
    pr(
        "Só listar alvos",
        "Resolve e lista os alvos sem enviar pacotes.",
        "Conferir o escopo antes de escanear.",
        0,
        &[("tec", "sL")],
    ),
    pr(
        "IPv6",
        "Scan padrão com serviços, em IPv6.",
        "Alvos IPv6 (-6).",
        3,
        &[("six", "1"), ("sV", "1")],
    ),
    pr(
        "Padrão + relatórios salvos",
        "Scan padrão com motivo de cada estado e arquivos nos 3 formatos.",
        "Quando o resultado precisa ser guardado ou entregue.",
        3,
        &[
            ("sV", "1"),
            ("reason", "1"),
            ("v", "v1"),
            ("oA", "relatorio"),
        ],
    ),
];

/// Opções preservadas ao aplicar um perfil.
const KEEP: [&str; 5] = ["targets", "iL", "iR", "exclude", "excludefile"];

pub fn apply(p: &Profile, current: &Values) -> Values {
    let mut v = Values::default();
    for id in KEEP {
        v.set(id, current.get(id));
    }
    for (id, val) in p.set {
        v.set(id, *val);
    }
    v
}

pub fn find(name: &str) -> Option<&'static Profile> {
    let n = name.to_lowercase();
    PROFILES
        .iter()
        .find(|p| p.name.to_lowercase() == n)
        .or_else(|| PROFILES.iter().find(|p| p.name.to_lowercase().contains(&n)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::{catalog, command, noise};

    #[test]
    fn dezesseis_perfis_com_ids_validos() {
        assert_eq!(PROFILES.len(), 16);
        assert_eq!(PROFILES.iter().filter(|p| p.recommended).count(), 1);
        for p in PROFILES {
            for (id, val) in p.set {
                let o = catalog::get(id).unwrap_or_else(|| panic!("{}: id {id}", p.name));
                if o.kind == catalog::Kind::Choice {
                    assert!(o.choice(val).is_some(), "{}: valor {val} em {id}", p.name);
                }
            }
        }
    }

    #[test]
    fn ruido_declarado_bate_com_o_calculado() {
        let bad: Vec<String> = PROFILES
            .iter()
            .filter_map(|p| {
                let got = noise::estimate(&apply(p, &Values::default())).level;
                (got != p.noise)
                    .then(|| format!("{}: declarado {} calculado {got}", p.name, p.noise))
            })
            .collect();
        assert!(bad.is_empty(), "{bad:?}");
    }

    #[test]
    fn aplicar_mantem_alvos_e_restaura_o_resto() {
        let mut cur = Values::default();
        cur.set("targets", "192.0.2.10");
        cur.set("exclude", "192.0.2.1");
        cur.set("T", "T5");
        cur.set("oN", "x.txt");
        let v = apply(find("rápido").unwrap(), &cur);
        assert_eq!(
            command::display(&command::build(&v)),
            "nmap -F -T4 --exclude 192.0.2.1 192.0.2.10"
        );
        assert_eq!(v.get("oN"), "");
    }

    #[test]
    fn comandos_dos_perfis_principais() {
        let d = |n: &str| {
            command::display(&command::build(&apply(
                find(n).unwrap(),
                &Values::default(),
            )))
        };
        assert_eq!(d("Padrão com serviços"), "nmap -sV scanme.nmap.org");
        assert_eq!(d("Discreto"), "nmap -sS -Pn -n -T2 -f scanme.nmap.org");
        assert_eq!(d("Mapear"), "nmap -sA -F scanme.nmap.org");
        assert_eq!(
            d("Sites"),
            "nmap -p 80,443,8080,8443 -sV --script=http-title,http-headers,http-methods,ssl-cert scanme.nmap.org"
        );
        assert_eq!(
            d("relatórios"),
            "nmap -sV -oA relatorio -v --reason scanme.nmap.org"
        );
    }
}
