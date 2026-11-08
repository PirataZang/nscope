//! Base de conhecimento local: portas comuns, estados de porta e scripts NSE populares.

/// Nível de atenção de um serviço/script.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Risk {
    Info,
    Attention,
    High,
}

impl Risk {
    /// Rótulo para um serviço exposto.
    pub fn exposure_label(self) -> &'static str {
        match self {
            Risk::Info => "Sobre este serviço",
            Risk::Attention => "Atenção",
            Risk::High => "Risco alto se exposto",
        }
    }
}

pub struct PortInfo {
    pub port: u16,
    pub name: &'static str,
    pub text: &'static str,
    pub risk: Risk,
}

use Risk::{Attention as A, High as H, Info as I};

const fn p(port: u16, name: &'static str, risk: Risk, text: &'static str) -> PortInfo {
    PortInfo {
        port,
        name,
        text,
        risk,
    }
}

static PORTS: &[PortInfo] = &[
    p(
        21,
        "FTP",
        A,
        "Transferência de arquivos. As credenciais viajam sem criptografia; prefira SFTP.",
    ),
    p(
        22,
        "SSH",
        I,
        "Acesso remoto seguro ao terminal. É esperado em servidores; use chaves e desative login por senha e como root.",
    ),
    p(
        23,
        "Telnet",
        H,
        "Acesso remoto SEM criptografia. Desative e use SSH.",
    ),
    p(
        25,
        "SMTP",
        A,
        "Envio de e-mail entre servidores. Não pode ficar aberto como relay.",
    ),
    p(
        53,
        "DNS",
        A,
        "Resolve nomes em IPs. Um servidor aberto pode ser abusado em ataques de amplificação.",
    ),
    p(
        80,
        "HTTP",
        I,
        "Sites sem criptografia. Verifique se redireciona para HTTPS.",
    ),
    p(110, "POP3", A, "E-mail sem criptografia."),
    p(
        111,
        "rpcbind",
        A,
        "Mapeia serviços RPC; costuma revelar NFS. Não deveria estar exposto.",
    ),
    p(
        123,
        "NTP",
        A,
        "Sincronização de horário. Servidores mal configurados são usados em ataques de amplificação.",
    ),
    p(
        135,
        "MSRPC",
        A,
        "RPC do Windows. Não deve ficar exposto à internet.",
    ),
    p(139, "NetBIOS", A, "Compartilhamento legado do Windows."),
    p(143, "IMAP", A, "E-mail sem criptografia."),
    p(
        161,
        "SNMP",
        A,
        "Gerenciamento de dispositivos. A comunidade padrão \"public\" é uma falha muito comum.",
    ),
    p(
        389,
        "LDAP",
        A,
        "Diretório de usuários. Costuma conter dados sensíveis.",
    ),
    p(
        443,
        "HTTPS",
        I,
        "Sites com criptografia. Confira o certificado e as versões do TLS.",
    ),
    p(
        445,
        "SMB",
        H,
        "Compartilhamento de arquivos do Windows. Alvo frequente de ransomware; nunca exponha à internet.",
    ),
    p(
        1433,
        "SQL Server",
        H,
        "Banco de dados. Não deve ficar acessível pela rede aberta.",
    ),
    p(
        1521,
        "Oracle",
        H,
        "Banco de dados. Não deve ficar acessível pela rede aberta.",
    ),
    p(
        2049,
        "NFS",
        A,
        "Compartilhamento de arquivos Unix. Verifique a quem está exportado.",
    ),
    p(
        2375,
        "Docker API",
        H,
        "API do Docker sem TLS dá controle total do servidor.",
    ),
    p(
        3306,
        "MySQL",
        H,
        "Banco de dados. Não deve ficar acessível pela rede aberta.",
    ),
    p(
        3389,
        "RDP",
        H,
        "Área de trabalho remota do Windows. Muito atacada por força bruta.",
    ),
    p(
        5432,
        "PostgreSQL",
        H,
        "Banco de dados. Não deve ficar acessível pela rede aberta.",
    ),
    p(
        5900,
        "VNC",
        H,
        "Área de trabalho remota, muitas vezes com senha fraca.",
    ),
    p(5985, "WinRM", A, "Administração remota do Windows."),
    p(
        6379,
        "Redis",
        H,
        "Banco em memória, frequentemente sem senha.",
    ),
    p(
        8080,
        "HTTP alternativo",
        A,
        "Costuma ser painel, proxy ou aplicação de desenvolvimento.",
    ),
    p(
        8443,
        "HTTPS alternativo",
        A,
        "Costuma ser painel de administração.",
    ),
    p(
        9200,
        "Elasticsearch",
        H,
        "Busca e logs; instâncias abertas vazam dados.",
    ),
    p(
        11211,
        "Memcached",
        H,
        "Cache em memória; aberto, serve para ataques de amplificação.",
    ),
    p(
        27017,
        "MongoDB",
        H,
        "Banco de dados; instâncias sem senha vazam dados.",
    ),
];

pub fn port_info(port: u16) -> Option<&'static PortInfo> {
    PORTS.iter().find(|p| p.port == port)
}

pub fn state_help(state: &str) -> &'static str {
    match state {
        "open" => "Há um serviço escutando e aceitando conexões.",
        "closed" => "A porta responde, mas nenhum serviço está escutando.",
        "filtered" => "Um firewall (ou filtro) bloqueia: o nmap não consegue saber se está aberta.",
        "unfiltered" => {
            "A porta está acessível, mas o nmap não sabe dizer se está aberta ou fechada (típico do ACK scan)."
        }
        "open|filtered" => {
            "O nmap não consegue distinguir entre aberta e filtrada (comum em UDP e nos scans Null/FIN/Xmas)."
        }
        "closed|filtered" => {
            "Não dá para distinguir entre fechada e filtrada (típico do idle scan)."
        }
        _ => "Estado não reconhecido pelo nscope.",
    }
}

pub const STATES: [&str; 6] = [
    "open",
    "closed",
    "filtered",
    "unfiltered",
    "open|filtered",
    "closed|filtered",
];

/// (nome, descrição, risco) das categorias NSE.
pub static NSE_CATEGORIES: &[(&str, &str, Risk)] = &[
    ("default", "Seguros e úteis; é o que -sC executa.", I),
    ("safe", "Não deveriam afetar o alvo.", I),
    (
        "discovery",
        "Descobrem mais informações da rede e dos serviços.",
        I,
    ),
    ("version", "Ampliam a detecção de versão.", I),
    (
        "auth",
        "Verificam métodos de autenticação (ex.: login anônimo).",
        I,
    ),
    (
        "broadcast",
        "Descobrem hosts por broadcast na rede local.",
        I,
    ),
    (
        "external",
        "Consultam serviços de terceiros (seus dados saem da rede).",
        A,
    ),
    ("vuln", "Verificam vulnerabilidades conhecidas.", A),
    ("malware", "Procuram sinais de malware e backdoors.", I),
    (
        "intrusive",
        "Podem consumir muitos recursos ou travar o alvo.",
        H,
    ),
    ("brute", "Tentam adivinhar senhas por força bruta.", H),
    (
        "fuzzer",
        "Enviam dados malformados para provocar falhas.",
        H,
    ),
    ("dos", "Podem causar negação de serviço.", H),
    ("exploit", "Tentam explorar vulnerabilidades ativamente.", H),
];

/// Scripts populares (curados): (nome, descrição, risco).
pub static NSE_POPULAR: &[(&str, &str, Risk)] = &[
    ("http-title", "Mostra o título da página web.", I),
    ("http-headers", "Mostra os cabeçalhos HTTP da resposta.", I),
    (
        "http-methods",
        "Lista os métodos HTTP aceitos (PUT e DELETE em servidores públicos são sinal de alerta).",
        I,
    ),
    (
        "http-enum",
        "Procura diretórios e aplicações web conhecidos. Faz muitas requisições.",
        A,
    ),
    (
        "ssl-cert",
        "Mostra o certificado TLS: emissor, validade e nomes.",
        I,
    ),
    (
        "ssl-enum-ciphers",
        "Lista as cifras TLS aceitas e dá uma nota.",
        A,
    ),
    ("ssh-hostkey", "Mostra as chaves do servidor SSH.", I),
    (
        "ssh-auth-methods",
        "Mostra os métodos de login aceitos pelo SSH.",
        I,
    ),
    (
        "smb-os-discovery",
        "Descobre SO, nome e domínio via SMB.",
        I,
    ),
    (
        "smb-security-mode",
        "Verifica a segurança do SMB (assinatura, contas).",
        I,
    ),
    (
        "smb-protocols",
        "Lista as versões do protocolo SMB aceitas.",
        I,
    ),
    (
        "smb-vuln-ms17-010",
        "Verifica se o SMB tem a falha MS17-010 (EternalBlue).",
        A,
    ),
    ("ftp-anon", "Verifica se o FTP aceita login anônimo.", I),
    (
        "banner",
        "Captura o banner que o serviço mostra ao conectar.",
        I,
    ),
    ("mysql-info", "Mostra versão e capacidades do MySQL.", I),
    (
        "rdp-enum-encryption",
        "Mostra a criptografia aceita pelo RDP.",
        I,
    ),
    ("dns-brute", "Adivinha subdomínios por força bruta.", H),
    ("ssh-brute", "Tenta senhas no SSH por força bruta.", H),
];

/// Risco de um item da lista de `--script` (categoria ou script curado); `None` se desconhecido.
pub fn script_risk(name: &str) -> Option<Risk> {
    NSE_CATEGORIES
        .iter()
        .chain(NSE_POPULAR)
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, r)| *r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_de_portas() {
        assert_eq!(port_info(22).unwrap().name, "SSH");
        assert_eq!(port_info(6379).unwrap().risk, Risk::High);
        assert!(port_info(1).is_none());
        let mut seen = std::collections::HashSet::new();
        assert!(PORTS.iter().all(|p| seen.insert(p.port)));
        for s in STATES {
            assert!(!state_help(s).starts_with("Estado não"));
        }
    }

    #[test]
    fn risco_de_scripts() {
        assert_eq!(script_risk("brute"), Some(Risk::High));
        assert_eq!(script_risk("ssh-brute"), Some(Risk::High));
        assert_eq!(script_risk("http-title"), Some(Risk::Info));
        assert_eq!(script_risk("nada"), None);
        assert!(Risk::High > Risk::Attention);
    }
}
