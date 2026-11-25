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

/// Uma execução da sessão, guardada em memória até o usuário salvar o histórico.
#[derive(Clone, Debug)]
pub struct Execution {
    /// Data e hora do início (`2026-11-25_12-30-05`).
    pub when: String,
    pub command: String,
    /// Situação em palavras: "concluído", "cancelado", "falhou: ...".
    pub status: String,
    pub secs: u64,
    pub result: Option<ScanResult>,
    pub xml: Option<String>,
    /// Saída do nmap como apareceu na aba Execução.
    pub log: Vec<String>,
}

impl Execution {
    /// `12:30:05`
    pub fn clock(&self) -> String {
        self.when.get(11..).unwrap_or("").replace('-', ":")
    }
    pub fn open_ports(&self) -> usize {
        self.result
            .as_ref()
            .map_or(0, |r| r.hosts.iter().map(|h| h.open_count()).sum())
    }
}

/// Cria o arquivo sem sobrescrever nada (`create_new`) e devolve ao usuário do sudo.
fn write_new(path: &Path, text: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(text.as_bytes())?;
    crate::util::give_back(path);
    Ok(())
}

fn execution_md(n: usize, e: &Execution) -> String {
    let head = format!(
        "> Execução {n} · {} às {} · {} · {} s\n\n",
        e.when.get(..10).unwrap_or(""),
        e.clock(),
        cell(&e.status),
        e.secs
    );
    match &e.result {
        Some(r) => {
            let body = render(r);
            body.replacen("\n\n", &format!("\n\n{head}"), 1)
        }
        None => format!(
            "# Execução {n}\n\n{head}## Comando\n\n```\n{}\n```\n\nEsta execução não gerou resultados. A saída do nmap está no arquivo `-saida.txt` ao lado.\n",
            e.command.replace("```", "'''")
        ),
    }
}

/// Salva todas as execuções numa pasta nova dentro de `dir`:
/// `nscope-historico-<data>/` com `README.md` (índice) e, por execução, relatório `.md`,
/// XML do nmap (`.xml`, reabre com `nscope --open`) e a saída em texto (`-saida.txt`).
pub fn save_history(list: &[Execution], dir: &Path, stamp: &str) -> std::io::Result<PathBuf> {
    let mut folder = None;
    for n in 1..100 {
        let name = if n == 1 {
            format!("nscope-historico-{stamp}")
        } else {
            format!("nscope-historico-{stamp}-{n}")
        };
        let p = dir.join(name);
        match std::fs::create_dir(&p) {
            Ok(()) => {
                folder = Some(p);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let folder = folder.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "já existem pastas de histórico demais com este nome",
        )
    })?;
    crate::util::give_back(&folder);

    let mut idx = String::from("# Histórico de execuções do nscope\n\n");
    idx.push_str(&format!(
        "> Salvo em {} às {}. {} {}. Use apenas com autorização.\n\n",
        stamp.get(..10).unwrap_or(""),
        stamp.get(11..).unwrap_or("").replace('-', ":"),
        list.len(),
        if list.len() == 1 {
            "execução"
        } else {
            "execuções"
        }
    ));
    idx.push_str("| # | Hora | Comando | Situação | Hosts ligados | Portas abertas | Arquivos |\n");
    idx.push_str("|---|---|---|---|---|---|---|\n");
    for (i, e) in list.iter().enumerate() {
        let n = i + 1;
        let base = format!("{n:02}_{}", e.when.get(11..).unwrap_or("execucao"));
        write_new(&folder.join(format!("{base}.md")), &execution_md(n, e))?;
        let mut files = vec![format!("[relatório]({base}.md)")];
        if let Some(x) = &e.xml {
            write_new(&folder.join(format!("{base}.xml")), x)?;
            files.push(format!("[XML]({base}.xml)"));
        }
        if !e.log.is_empty() {
            let mut log = e.log.join("\n");
            log.push('\n');
            write_new(&folder.join(format!("{base}-saida.txt")), &log)?;
            files.push(format!("[saída]({base}-saida.txt)"));
        }
        let hosts = e.result.as_ref().map_or("-".to_string(), |r| {
            format!(
                "{} de {}",
                r.hosts_up,
                r.hosts_total.max(r.hosts.len() as u32)
            )
        });
        idx.push_str(&format!(
            "| {n} | {} | `{}` | {} ({} s) | {hosts} | {} | {} |\n",
            e.clock(),
            cell(&e.command),
            cell(&e.status),
            e.secs,
            e.open_ports(),
            files.join(" · ")
        ));
    }
    idx.push_str("\nPara reabrir um resultado no nscope: `nscope --open <arquivo>.xml`.\n");
    write_new(&folder.join("README.md"), &idx)?;
    Ok(folder)
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

    fn exec(result: Option<ScanResult>, status: &str) -> Execution {
        Execution {
            when: "2026-11-25_12-30-05".into(),
            command: "nmap -sV 192.0.2.0/24".into(),
            status: status.into(),
            secs: 14,
            xml: result.as_ref().map(|_| "<nmaprun/>".into()),
            result,
            log: vec!["Starting Nmap".into()],
        }
    }

    #[test]
    fn historico_vira_pasta_organizada_sem_sobrescrever() {
        let dir = std::env::temp_dir().join(format!("nscope-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = [exec(Some(sample()), "concluído"), exec(None, "cancelado")];
        let a = save_history(&list, &dir, "2026-11-25_12-40-00").unwrap();
        let b = save_history(&list, &dir, "2026-11-25_12-40-00").unwrap();
        assert!(a.ends_with("nscope-historico-2026-11-25_12-40-00"));
        assert!(b.to_string_lossy().ends_with("-2"));
        let idx = std::fs::read_to_string(a.join("README.md")).unwrap();
        assert!(
            idx.contains(
                "| 1 | 12:30:05 | `nmap -sV 192.0.2.0/24` | concluído (14 s) | 2 de 3 | 3 |"
            ),
            "{idx}"
        );
        assert!(idx.contains("| 2 | 12:30:05 |") && idx.contains("cancelado"));
        assert!(a.join("01_12-30-05.xml").exists() && !a.join("02_12-30-05.xml").exists());
        assert!(
            std::fs::read_to_string(a.join("02_12-30-05.md"))
                .unwrap()
                .contains("não gerou resultados")
        );
        assert!(
            std::fs::read_to_string(a.join("01_12-30-05.md"))
                .unwrap()
                .contains("> Execução 1")
        );
        assert_eq!(
            std::fs::read_to_string(a.join("01_12-30-05-saida.txt")).unwrap(),
            "Starting Nmap\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
