//! Validação por lista de permitidos: alvos, portas, tempos, números e flags extras.
//! Nenhuma função aqui executa nada; só aceita ou explica (em português) como corrigir.

use super::catalog::Validator;

pub const MAX_TARGETS: usize = 64;
pub const MAX_TARGET_LEN: usize = 253;
pub const MAX_VALUE_LEN: usize = 1024;

/// Separa alvos por espaço/vírgula (sem validar).
pub fn split_targets(s: &str) -> Vec<&str> {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|p| !p.is_empty())
        .collect()
}

/// Valida a lista de alvos. Devolve os alvos únicos, na ordem digitada.
pub fn targets(s: &str) -> Result<Vec<String>, String> {
    let parts = split_targets(s);
    if parts.is_empty() {
        return Err("Informe pelo menos um alvo (ex.: 192.168.0.1 ou scanme.nmap.org).".into());
    }
    if parts.len() > MAX_TARGETS {
        return Err(format!(
            "Muitos alvos ({}; máximo {MAX_TARGETS}). Use uma rede, ex.: 192.168.0.0/24, ou -iL com um arquivo.",
            parts.len()
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for p in parts {
        if p.starts_with('-') {
            return Err(format!(
                "\"{p}\" começa com \"-\": o nmap leria isso como uma opção, não como alvo. Remova o hífen inicial."
            ));
        }
        if p.chars().count() > MAX_TARGET_LEN {
            return Err(format!(
                "Um dos alvos tem mais de {MAX_TARGET_LEN} caracteres. Confira se não colou texto por engano."
            ));
        }
        if let Some(bad) = p
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || ".-_:/*%[]".contains(*c)))
        {
            return Err(format!(
                "Caractere não permitido em \"{p}\": \"{}\". Use só letras, dígitos e . - _ : / * % [ ].",
                bad.escape_default()
            ));
        }
        if let Some((_, mask)) = p.split_once('/')
            && (mask.is_empty()
                || !mask.bytes().all(|b| b.is_ascii_digit())
                || mask.len() > 3
                || mask.parse::<u32>().is_ok_and(|m| m > 128))
        {
            return Err(format!(
                "Máscara inválida em \"{p}\": depois da barra use só dígitos, até 128 (ex.: /24)."
            ));
        }
        if !out.iter().any(|x| x == p) {
            out.push(p.to_string());
        }
    }
    Ok(out)
}

fn all_ctl_free(v: &str) -> Result<(), String> {
    if v.chars().count() > MAX_VALUE_LEN {
        return Err(format!(
            "valor longo demais (máximo {MAX_VALUE_LEN} caracteres)."
        ));
    }
    if v.chars().any(char::is_control) {
        return Err("o valor não pode ter quebras de linha nem caracteres de controle.".into());
    }
    Ok(())
}

pub fn int(v: &str, min: u64, max: u64) -> Result<u64, String> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err("use apenas números inteiros (sem sinal nem espaços).".into());
    }
    let n: u64 = v
        .parse()
        .map_err(|_| format!("use um valor entre {min} e {max}."))?;
    if n < min || n > max {
        return Err(format!("use um valor entre {min} e {max}."));
    }
    Ok(n)
}

pub fn time(v: &str) -> Result<(), String> {
    let err = || {
        "tempo inválido. Exemplos: 500ms, 30s, 5m, 2h (ou só um número, em segundos).".to_string()
    };
    let body = ["ms", "s", "m", "h"]
        .iter()
        .find_map(|u| v.strip_suffix(u))
        .unwrap_or(v);
    let (int_part, frac) = match body.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (body, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if digits(int_part) && frac.is_none_or(digits) {
        Ok(())
    } else {
        Err(err())
    }
}

fn port_number(s: &str) -> Result<u32, String> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("\"{s}\" não é um número de porta."));
    }
    let n: u32 = s.parse().map_err(|_| "porta inválida.".to_string())?;
    if n > 65535 {
        return Err(format!("porta {n} fora da faixa (0 a 65535)."));
    }
    Ok(n)
}

/// Lista de portas: números, faixas (1-1024, -100, 100-), "-" e prefixos T:/U:/S:.
pub fn ports(v: &str) -> Result<(), String> {
    if v.is_empty() {
        return Err("lista de portas vazia.".into());
    }
    for item in v.split(',') {
        let mut it = item;
        if let Some((pre, rest)) = item.split_once(':') {
            if !matches!(pre, "T" | "U" | "S" | "t" | "u" | "s") {
                return Err(format!(
                    "prefixo \"{pre}:\" inválido. Use T: (TCP), U: (UDP) ou S: (SCTP)."
                ));
            }
            it = rest;
        }
        if it.is_empty() {
            return Err("item vazio na lista (vírgula sobrando?).".into());
        }
        if it == "-" {
            continue;
        }
        match it.split_once('-') {
            None => {
                port_number(it)?;
            }
            Some((a, b)) => {
                let lo = if a.is_empty() { 0 } else { port_number(a)? };
                let hi = if b.is_empty() { 65535 } else { port_number(b)? };
                if lo > hi {
                    return Err(format!(
                        "faixa \"{it}\" invertida: o início é maior que o fim."
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn protos(v: &str) -> Result<(), String> {
    for item in v.split(',') {
        let parts: Vec<&str> = item.split('-').collect();
        if parts.len() > 2 || parts.iter().any(|p| int(p, 0, 255).is_err()) {
            return Err("use números de protocolo (0 a 255) separados por vírgula.".into());
        }
    }
    Ok(())
}

pub fn ratio(v: &str) -> Result<(), String> {
    let ok = v.parse::<f64>().is_ok_and(|x| (0.0..=1.0).contains(&x))
        && v.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    if ok {
        Ok(())
    } else {
        Err("use um número entre 0.0 e 1.0.".into())
    }
}

pub fn hex(v: &str) -> Result<(), String> {
    let h = v.strip_prefix("0x").unwrap_or(v);
    if !h.is_empty() && h.len().is_multiple_of(2) && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("use pares de dígitos hexadecimais (ex.: DEADBEEF).".into())
    }
}

pub fn scanflags(v: &str) -> Result<(), String> {
    if v.bytes().all(|b| b.is_ascii_digit()) {
        return int(v, 0, 255)
            .map(|_| ())
            .map_err(|_| "o número das flags deve estar entre 0 e 255.".into());
    }
    let up = v.to_ascii_uppercase();
    let mut rest = up.as_str();
    while !rest.is_empty() {
        let hit = [
            "URG", "ACK", "PSH", "RST", "SYN", "FIN", "ECE", "CWR", "ALL", "NONE",
        ]
        .iter()
        .find(|f| rest.starts_with(**f));
        match hit {
            Some(f) => rest = &rest[f.len()..],
            None => return Err(
                "use nomes de flags colados (URG ACK PSH RST SYN FIN, ex.: SYNFIN) ou um número."
                    .into(),
            ),
        }
    }
    Ok(())
}

pub fn mac(v: &str) -> Result<(), String> {
    if v.len() <= 40
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" :-".contains(&b))
    {
        Ok(())
    } else {
        Err(
            "use 0 (aleatório), um MAC (aa:bb:cc:dd:ee:ff), um prefixo ou o nome de um fabricante."
                .into(),
        )
    }
}

pub fn decoys(v: &str) -> Result<(), String> {
    for d in v.split(',') {
        let ok = !d.is_empty()
            && d.len() <= 253
            && d.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b));
        if !ok {
            return Err(
                "iscas: IPs, nomes, ME ou RND:n separados por vírgula (ex.: RND:5,ME).".into(),
            );
        }
    }
    Ok(())
}

/// Valida o valor de uma opção. Valor vazio é sempre aceito (= desligada).
pub fn value(v: &Validator, raw: &str) -> Result<(), String> {
    let v_ = raw.trim();
    if v_.is_empty() {
        return Ok(());
    }
    all_ctl_free(v_)?;
    match v {
        Validator::Free => Ok(()),
        Validator::Int { min, max } => int(v_, *min, *max).map(|_| ()),
        Validator::IntMul { min, max, mul } => {
            let n = int(v_, *min, *max)?;
            if n % mul == 0 {
                Ok(())
            } else {
                Err(format!("deve ser múltiplo de {mul}."))
            }
        }
        Validator::Time => time(v_),
        Validator::Ports => ports(v_),
        Validator::Protos => protos(v_),
        Validator::Ratio => ratio(v_),
        Validator::Hex => hex(v_),
        Validator::ScanFlags => scanflags(v_),
        Validator::Mac => mac(v_),
        Validator::Decoys => decoys(v_),
    }
}

/// Flags que o nscope controla (ou que têm campo próprio) e que o campo livre não pode repetir.
const RESERVED: [&str; 7] = [
    "-oN",
    "-oX",
    "-oG",
    "-oS",
    "-oA",
    "--stats-every",
    "--noninteractive",
];

/// Tokeniza o campo de flags extras (regras de shell só para separar; nunca executa em shell).
pub fn extra_args(s: &str) -> Result<Vec<String>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(vec![]);
    }
    all_ctl_free(s)?;
    if let Some(c) = s.chars().find(|c| ";&|\\$<>()`".contains(*c)) {
        return Err(format!(
            "caractere \"{c}\" não é aceito: aqui não há shell, então ele não faria o que parece (e poderia confundir quem copiar o comando). Digite só opções do nmap."
        ));
    }
    let toks = shell_words::split(s)
        .map_err(|_| "aspas abertas ou mal fechadas no campo de flags extras.".to_string())?;
    for t in &toks {
        let name = t.split('=').next().unwrap_or(t);
        let o_flag = name.len() > 3
            && name.starts_with("-o")
            && matches!(&name[..3], "-oN" | "-oX" | "-oG" | "-oS" | "-oA");
        if RESERVED.contains(&name) || o_flag {
            return Err(format!(
                "\"{name}\" tem campo próprio na aba Saída (o nscope precisa conhecê-lo para ler os resultados). Use lá."
            ));
        }
    }
    Ok(toks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alvos_validos() {
        assert_eq!(targets("192.168.0.1, scanme.nmap.org 10.0.0.0/8 192.168.0-3.* fe80::1%eth0 [::1] 192.168.0.1").unwrap().len(), 6);
    }

    #[test]
    fn alvos_invalidos() {
        for bad in [
            "",
            "   ",
            "-sS",
            "a;b",
            "a b$",
            "10.0.0.0/abc",
            "10.0.0.0/129",
            "10.0.0.0/",
            "h`id`",
            "a\nb;c",
            "$(x)",
            "é.com",
        ] {
            assert!(targets(bad).is_err(), "deveria rejeitar {bad:?}");
        }
        assert!(targets(&"a ".repeat(65)).is_err());
        assert!(targets(&"a".repeat(254)).is_err());
        assert!(targets("ok --script=x").is_err());
    }

    #[test]
    fn nenhum_alvo_aceito_comeca_com_hifen_nem_tem_metacaractere() {
        // varredura determinística de caracteres e posições (substitui proptest)
        let chars: Vec<char> = (0u8..=127)
            .map(char::from)
            .chain("éß\u{202e}\u{200b}".chars())
            .collect();
        for &a in &chars {
            for &b in &chars {
                let s = format!("{a}{b}x");
                if let Ok(v) = targets(&s) {
                    for t in v {
                        assert!(!t.starts_with('-'));
                        assert!(
                            t.chars()
                                .all(|c| c.is_ascii_alphanumeric() || ".-_:/*%[]".contains(c)),
                            "{t:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn inteiros() {
        assert_eq!(int("7", 0, 9), Ok(7));
        for bad in [
            "",
            "-1",
            "+1",
            "1.5",
            " 1",
            "10",
            "abc",
            "99999999999999999999",
        ] {
            assert!(int(bad, 0, 9).is_err(), "{bad}");
        }
    }

    #[test]
    fn tempos() {
        for ok in ["500ms", "30s", "5m", "2h", "10", "1.5s", "0.5"] {
            assert!(time(ok).is_ok(), "{ok}");
        }
        for bad in ["", "s", "1x", "1.s", ".5s", "-1s", "1 s", "1.2.3"] {
            assert!(time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn portas() {
        for ok in [
            "80",
            "22,80,443",
            "1-1024",
            "T:80,U:53",
            "-",
            "-100",
            "100-",
            "S:132",
            "0",
            "65535",
            "T:1-5,U:9",
        ] {
            assert!(ports(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "65536", "80,", ",80", "a", "X:80", "10-5", "T:", "80;81", "1-2-3", "-5-",
        ] {
            assert!(ports(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn outros_validadores() {
        assert!(
            value(
                &Validator::IntMul {
                    min: 8,
                    max: 65528,
                    mul: 8
                },
                "16"
            )
            .is_ok()
        );
        assert!(
            value(
                &Validator::IntMul {
                    min: 8,
                    max: 65528,
                    mul: 8
                },
                "10"
            )
            .is_err()
        );
        assert!(
            value(
                &Validator::IntMul {
                    min: 8,
                    max: 65528,
                    mul: 8
                },
                "0"
            )
            .is_err()
        );
        assert!(hex("DEADBEEF").is_ok() && hex("0xdead").is_ok());
        assert!(hex("ABC").is_err() && hex("").is_err() && hex("ZZ").is_err());
        assert!(
            scanflags("SYNFIN").is_ok()
                && scanflags("urgpshfin").is_ok()
                && scanflags("255").is_ok()
        );
        assert!(scanflags("256").is_err() && scanflags("FOO").is_err());
        assert!(
            ratio("0.5").is_ok()
                && ratio("1").is_ok()
                && ratio("1.1").is_err()
                && ratio("-0.1").is_err()
                && ratio("1e0").is_err()
        );
        assert!(
            mac("0").is_ok()
                && mac("aa:bb:cc:dd:ee:ff").is_ok()
                && mac("Apple").is_ok()
                && mac("a;b").is_err()
        );
        assert!(
            decoys("RND:5,ME").is_ok() && decoys("1.2.3.4,,ME").is_err() && decoys("a b").is_err()
        );
        assert!(protos("1,2,4").is_ok() && protos("1-5").is_ok() && protos("256").is_err());
        assert!(value(&Validator::Free, "a\nb").is_err());
        assert!(value(&Validator::Free, "  ").is_ok());
    }

    #[test]
    fn flags_extras() {
        assert_eq!(
            extra_args("--nsock-engine epoll").unwrap(),
            ["--nsock-engine", "epoll"]
        );
        assert_eq!(
            extra_args("--script-args 'a b=c'").unwrap(),
            ["--script-args", "a b=c"]
        );
        assert!(extra_args("").unwrap().is_empty());
        for bad in [
            "-sS; rm -rf /",
            "a | b",
            "a & b",
            "$(id)",
            "`id`",
            "a > f",
            "a < f",
            "(x)",
            "a\\b",
            "'aberta",
            "-oX /tmp/x",
            "-oA rel",
            "-oN=x",
            "--stats-every 5s",
            "a\nb",
        ] {
            assert!(extra_args(bad).is_err(), "deveria rejeitar {bad:?}");
        }
        assert!(extra_args("--open").is_ok());
    }
}
