//! Exportação do resultado em Markdown. O arquivo é criado com `create_new` (nunca sobrescreve
//! nem segue link simbólico: `O_EXCL` falha se o caminho já existe, inclusive como symlink).

use crate::nmap::xml::{Host, ScanResult};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Escapa um valor para célula de tabela Markdown.
fn cell(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
        .replace('`', "'")
}

fn host_title(h: &Host) -> String {
    if h.hostname.is_empty() {
        h.address.clone()
    } else {
        format!("{} ({})", h.hostname, h.address)
    }
}

pub fn render(r: &ScanResult) -> String {
    let mut o = String::new();
    o.push_str("# Relatório nscope\n\n");
    o.push_str("> Gerado pelo nscope a partir da saída do nmap. Use apenas com autorização.\n\n");
    o.push_str("## Comando\n\n```\n");
    o.push_str(&r.command.replace("```", "'''"));
    o.push_str("\n```\n\n## Resumo\n\n");
    if !r.started.is_empty() {
        o.push_str(&format!("- Início: {}\n", cell(&r.started)));
    }
    if let Some(d) = r.duration_secs {
        o.push_str(&format!("- Duração: {d:.1} s\n"));
    }
    o.push_str(&format!(
        "- Hosts: {} ligados, {} desligados, {} no total\n",
        r.hosts_up, r.hosts_down, r.hosts_total
    ));
    if !r.summary.is_empty() {
        o.push_str(&format!("- {}\n", cell(&r.summary)));
    }
    for w in &r.warnings {
        o.push_str(&format!("- Aviso: {}\n", cell(w)));
    }
    for h in &r.hosts {
        o.push_str(&format!("\n## {}\n\n", cell(&host_title(h))));
        o.push_str(&format!("- Estado: {}\n", cell(&h.state)));
        if !h.mac.is_empty() {
            o.push_str(&format!("- MAC: {}\n", cell(&h.mac)));
        }
        if let Some(os) = &h.os {
            o.push_str(&format!(
                "- Sistema operacional (estimado): {} ({}%)\n",
                cell(&os.name),
                cell(&os.accuracy)
            ));
        }
        if !h.ports.is_empty() {
            o.push_str("\n| Porta | Estado | Serviço | Versão |\n|---|---|---|---|\n");
            for p in &h.ports {
                o.push_str(&format!(
                    "| {}/{} | {} | {} | {} |\n",
                    p.number,
                    cell(&p.protocol),
                    cell(&p.state),
                    cell(&p.service),
                    cell(&p.version_text())
                ));
            }
        }
        for x in &h.hidden {
            o.push_str(&format!(
                "\nNão exibidas: {} portas {} ({})\n",
                x.count,
                cell(&x.state),
                cell(&x.reason)
            ));
        }
        let scripts: Vec<_> = h
            .ports
            .iter()
            .flat_map(|p| {
                p.scripts
                    .iter()
                    .map(move |s| (format!("{}/{}", p.number, p.protocol), s))
            })
            .collect();
        if !scripts.is_empty() || !h.scripts.is_empty() {
            o.push_str("\n### Scripts\n\n");
            for (port, s) in scripts {
                o.push_str(&format!(
                    "- `{}` na porta {}: {}\n",
                    cell(&s.id),
                    cell(&port),
                    cell(&s.output)
                ));
            }
            for s in &h.scripts {
                o.push_str(&format!(
                    "- `{}` (host): {}\n",
                    cell(&s.id),
                    cell(&s.output)
                ));
            }
        }
    }
    o
}

/// Salva em `dir`, escolhendo um nome livre (`relatorio-nscope.md`, `-2`, `-3`...).
pub fn save(r: &ScanResult, dir: &Path) -> std::io::Result<PathBuf> {
    let text = render(r);
    for n in 1..100 {
        let name = if n == 1 {
            "relatorio-nscope.md".to_string()
        } else {
            format!("relatorio-nscope-{n}.md")
        };
        let path = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(text.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "já existem relatórios demais nesta pasta",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::xml;

    fn sample() -> ScanResult {
        xml::parse(include_str!("../fixtures/basico.xml")).unwrap()
    }

    #[test]
    fn relatorio_tem_comando_resumo_e_tabela() {
        let md = render(&sample());
        assert!(md.contains("```\nnmap -sV -O --traceroute 192.0.2.0/24\n```"));
        assert!(md.contains("2 ligados, 1 desligados, 3 no total"));
        assert!(md.contains("## servidor.exemplo.test (192.0.2.10)"));
        assert!(
            md.contains("| 22/tcp | open | ssh | OpenSSH 8.9p1 (Ubuntu Linux; protocol 2.0) |")
        );
        assert!(md.contains("Não exibidas: 995 portas closed (resets)"));
    }

    #[test]
    fn escapa_pipes_e_quebras() {
        let mut r = sample();
        r.hosts[0].ports[0].service = "a|b\nc`d".into();
        r.command = "x ``` y".into();
        let md = render(&r);
        assert!(md.contains("| a\\|b c'd |"), "{md}");
        assert!(!md.contains("x ``` y"));
    }

    #[test]
    fn nao_sobrescreve_nem_segue_symlink() {
        let dir = std::env::temp_dir().join(format!("nscope-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = save(&sample(), &dir).unwrap();
        let b = save(&sample(), &dir).unwrap();
        assert_ne!(a, b);
        assert!(b.to_string_lossy().ends_with("-2.md"));
        #[cfg(unix)]
        {
            let alvo = dir.join("alvo-secreto.txt");
            std::fs::write(&alvo, "original").unwrap();
            std::os::unix::fs::symlink(&alvo, dir.join("relatorio-nscope-3.md")).unwrap();
            let c = save(&sample(), &dir).unwrap();
            assert!(c.to_string_lossy().ends_with("-4.md"));
            assert_eq!(std::fs::read_to_string(&alvo).unwrap(), "original");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
