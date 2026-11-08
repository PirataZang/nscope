//! Estimativa DIDÁTICA de visibilidade (0 a 5): quanto o scan tende a aparecer para o alvo.
//! Não é medição real: depende de firewalls, IDS e do ambiente.

use super::catalog::Values;

pub struct Noise {
    pub level: u8,
    pub label: &'static str,
    pub reasons: Vec<&'static str>,
}

pub const LABELS: [&str; 6] = [
    "mínima",
    "baixa",
    "média",
    "alta",
    "muito alta",
    "altíssima",
];

/// Barra textual: `███░░`.
pub fn meter(level: u8) -> String {
    let l = usize::from(level.min(5));
    format!("{}{}", "█".repeat(l), "░".repeat(5 - l))
}

pub fn estimate(v: &Values) -> Noise {
    let tec = v.get("tec");
    if tec == "sL" {
        return Noise {
            level: 0,
            label: LABELS[0],
            reasons: vec!["não envia pacotes aos alvos"],
        };
    }
    let mut n: i32 = 1;
    let mut why = Vec::new();
    let mut add = |d: i32, m: &'static str| {
        n += d;
        why.push(m);
    };
    if tec == "sn" {
        add(-1, "só descoberta de hosts");
    }
    if tec == "sT" {
        add(1, "conexões completas ficam nos logs");
    }
    if v.flag("sU") {
        add(1, "UDP gera muito tráfego");
    }
    match v.get("pmode") {
        "all" => add(2, "todas as portas"),
        "def" if tec != "sn" => add(1, "1000 portas"),
        "top" if v.text("topn").parse::<u32>().is_ok_and(|x| x >= 500) => add(1, "muitas portas"),
        _ => {}
    }
    if v.flag("A") {
        add(3, "modo agressivo");
    } else {
        if v.flag("sV") {
            add(1, "detecção de versão");
        }
        if v.flag("O") {
            add(1, "detecção de SO");
        }
        if v.flag("sC") || !v.text("script").is_empty() {
            add(1, "scripts");
        }
    }
    let sp = v.text("script").to_lowercase();
    if ["brute", "dos", "exploit", "fuzzer", "intrusive", "vuln"]
        .iter()
        .any(|w| sp.contains(w))
    {
        add(1, "scripts intrusivos");
    }
    match v.get("T") {
        "T4" => add(1, "velocidade agressiva"),
        "T5" => add(2, "velocidade insana"),
        "T0" | "T1" | "T2" => add(-1, "velocidade baixa"),
        _ => {}
    }
    if v.flag("f") || !v.text("mtu").is_empty() {
        add(-1, "pacotes fragmentados");
    }
    let level = n.clamp(0, 5) as u8;
    Noise {
        level,
        label: LABELS[usize::from(level)],
        reasons: why,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(sets: &[(&str, &str)]) -> u8 {
        let mut v = Values::default();
        for (k, x) in sets {
            v.set(k, *x);
        }
        estimate(&v).level
    }

    #[test]
    fn pontuacao() {
        assert_eq!(n(&[("tec", "sL")]), 0);
        assert_eq!(n(&[]), 2); // 1 + 1000 portas
        assert_eq!(n(&[("tec", "sn")]), 0);
        assert_eq!(n(&[("A", "1"), ("T", "T4")]), 5);
        assert_eq!(n(&[("pmode", "all"), ("sV", "1"), ("T", "T4")]), 5);
        assert_eq!(n(&[("tec", "sS"), ("Pn", "1"), ("T", "T2"), ("f", "1")]), 0);
        assert_eq!(n(&[("sU", "1"), ("pmode", "top"), ("topn", "500")]), 3);
        assert_eq!(n(&[("sV", "1"), ("script", "vuln")]), 5);
    }

    #[test]
    fn sempre_no_intervalo_e_com_motivos() {
        let mut v = Values::default();
        v.set("A", "1");
        v.set("T", "T5");
        v.set("pmode", "all");
        v.set("tec", "sT");
        let r = estimate(&v);
        assert_eq!(r.level, 5);
        assert!(!r.reasons.is_empty());
        assert_eq!(meter(3), "███░░");
        assert_eq!(meter(9), "█████");
    }
}
