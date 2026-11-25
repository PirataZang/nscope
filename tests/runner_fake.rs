//! Integração com um nmap FALSO (script sh): sem rede e sem o nmap real.
#![cfg(unix)]

use nscope::nmap::catalog::Values;
use nscope::nmap::runner::{MAX_LINE, Outcome, Plan, Runner};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct Fake {
    dir: PathBuf,
    bin: PathBuf,
    args: PathBuf,
}

impl Fake {
    fn new(name: &str, body: &str) -> Fake {
        let dir = std::env::temp_dir().join(format!("nscope-fake-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("nmap");
        let args = dir.join("args.txt");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/basico.xml");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nxml=\"\"; prev=\"\"\nfor a in \"$@\"; do [ \"$prev\" = \"-oX\" ] && xml=\"$a\"; prev=\"$a\"; done\nFIXTURE='{}'\n{body}\n",
            args.display(),
            fixture.display()
        );
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        Fake { dir, bin, args }
    }
    fn args(&self) -> Vec<String> {
        std::fs::read_to_string(&self.args)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const NORMAL: &str = r#"
echo "Starting Nmap 7.95 ( https://nmap.org )"
echo "SYN Stealth Scan Timing: About 23.40% done; ETC: 14:03 (0:00:12 remaining)"
echo "Discovered open port 22/tcp on 192.0.2.10"
printf 'banner malicioso: \033[2J\033]0;pwn\007fim\n'
echo "aviso no stderr" >&2
[ -n "$xml" ] && cp "$FIXTURE" "$xml"
exit 0
"#;

/// Várias threads de teste criam scripts e fazem fork ao mesmo tempo: o kernel pode responder
/// ETXTBSY ("Text file busy") a um exec. Tentar de novo é o conserto padrão (só nos testes).
fn start(f: &Fake, p: &Plan) -> Result<Runner, String> {
    let mut r = Runner::start(f.bin.as_os_str(), p);
    for _ in 0..50 {
        if !matches!(&r, Err(e) if e.contains("os error 26")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
        r = Runner::start(f.bin.as_os_str(), p);
    }
    r
}

fn plan(sets: &[(&str, &str)]) -> Plan {
    let mut v = Values::default();
    v.set("targets", "192.0.2.10");
    for (k, x) in sets {
        v.set(k, *x);
    }
    Plan::from_values(&v).unwrap()
}

fn drive(r: &mut Runner, limit: Duration) -> Vec<String> {
    let t0 = Instant::now();
    let mut lines = Vec::new();
    while r.is_running() {
        lines.extend(r.poll().into_iter().map(|m| m.text().to_string()));
        assert!(
            t0.elapsed() < limit,
            "estourou o tempo; linhas até agora: {}",
            lines.len()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    lines
}

#[test]
fn execucao_normal_progresso_xml_e_limpeza() {
    let f = Fake::new("normal", NORMAL);
    let mut r = start(&f, &plan(&[])).unwrap();
    let tmp = r.temp_path().unwrap().to_path_buf();
    assert!(tmp.is_dir());
    let lines = drive(&mut r, Duration::from_secs(10));
    assert_eq!(r.outcome, Some(Outcome::Finished { code: Some(0) }));
    assert!(lines.iter().any(|l| l.starts_with("Discovered open port")));
    assert!(lines.iter().any(|l| l == "aviso no stderr"));
    // texto malicioso do processo nunca chega ao terminal: ESC e BEL viram ·
    let evil = lines
        .iter()
        .find(|l| l.starts_with("banner malicioso"))
        .unwrap();
    assert_eq!(evil, "banner malicioso: ·[2J·]0;pwn·fim");
    assert!(lines.iter().all(|l| !l.chars().any(char::is_control)));
    assert_eq!(r.progress.as_ref().unwrap().percent, 23.4);
    let res = r.result.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(res.hosts.len(), 3);
    // argumentos internos: --stats-every 1s e -oX no temporário privado; alvo por último
    let a = f.args();
    assert_eq!(&a[..2], ["--stats-every", "1s"]);
    assert_eq!(a[2], "-oX");
    assert!(a[3].starts_with(tmp.to_str().unwrap()));
    assert_eq!(a.last().unwrap(), "192.0.2.10");
    assert!(
        r.xml.as_deref().is_some_and(|x| x.contains("<nmaprun")),
        "XML bruto guardado para o histórico"
    );
    assert!(!tmp.exists(), "temporário deve ser removido ao terminar");
}

#[test]
fn cada_execucao_entra_no_historico_e_s_salva_tudo_numa_pasta() {
    use nscope::app::{App, Env, Tab};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let f = Fake::new("historico", NORMAL);
    let mut a = App::new(Env {
        privileged: true,
        nmap: Ok("Nmap version 7.95".into()),
        program: f.bin.clone().into_os_string(),
    });
    let out = f.dir.join("onde-o-terminal-abriu");
    std::fs::create_dir_all(&out).unwrap();
    a.save_dir = out.clone();
    a.values.set("targets", "8.8.8.8"); // alvo externo: executa direto, sem janela de confirmação
    for _ in 0..2 {
        let t0 = Instant::now();
        a.request_run();
        assert!(a.is_running(), "deve executar sem pedir confirmação");
        while a.is_running() {
            a.tick();
            assert!(t0.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert_eq!(a.history.len(), 2);
    assert_eq!(a.hist_i, 1, "a última execução fica selecionada");
    assert!(
        a.history
            .iter()
            .all(|e| e.status == "concluído" && e.result.is_some())
    );
    a.select_run(0);
    assert!(a.result.is_some());
    a.set_tab(Tab::Resultados);
    a.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    let dirs: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|d| d.path())
        .collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let idx = std::fs::read_to_string(dirs[0].join("README.md")).unwrap();
    assert!(idx.contains("| 1 |") && idx.contains("| 2 |"), "{idx}");
    let files = std::fs::read_dir(&dirs[0]).unwrap().count();
    assert_eq!(
        files,
        1 + 2 * 3,
        "índice + (relatório, XML, saída) por execução"
    );
}

#[test]
fn xml_do_usuario_e_stats_do_usuario_sao_respeitados() {
    let f = Fake::new("userxml", NORMAL);
    let out = f.dir.join("meu.xml");
    let p = plan(&[("oX", out.to_str().unwrap()), ("statsevery", "5s")]);
    let mut r = start(&f, &p).unwrap();
    assert!(r.temp_path().is_none());
    drive(&mut r, Duration::from_secs(10));
    assert!(out.exists());
    assert_eq!(r.result.as_ref().unwrap().as_ref().unwrap().hosts.len(), 3);
    let a = f.args();
    assert_eq!(a.iter().filter(|x| *x == "--stats-every").count(), 1);
    assert_eq!(a.iter().filter(|x| *x == "-oX").count(), 1);
    assert!(a.contains(&"5s".to_string()));
}

#[test]
fn standalone_nao_adiciona_xml_nem_stats() {
    let f = Fake::new("stand", "echo 'Nmap version 7.95'\nexit 0");
    let mut r = start(&f, &plan(&[("V", "1")])).unwrap();
    assert!(r.temp_path().is_none());
    let lines = drive(&mut r, Duration::from_secs(10));
    assert_eq!(lines, ["Nmap version 7.95"]);
    assert!(r.result.is_none());
    assert_eq!(f.args(), ["-V", "192.0.2.10"]);
}

#[test]
fn falha_do_nmap_vira_mensagem_sem_panico() {
    let f = Fake::new("falha", "echo 'QUITTING!' >&2\nexit 3");
    let mut r = start(&f, &plan(&[])).unwrap();
    let tmp = r.temp_path().unwrap().to_path_buf();
    let lines = drive(&mut r, Duration::from_secs(10));
    assert_eq!(r.outcome, Some(Outcome::Finished { code: Some(3) }));
    assert_eq!(lines, ["QUITTING!"]);
    assert!(r.result.as_ref().unwrap().is_err());
    assert!(!tmp.exists());
}

#[test]
fn xml_corrompido_gera_erro_claro() {
    let f = Fake::new("xmlruim", "echo '<nmaprun><host>' > \"$xml\"\nexit 0");
    let mut r = start(&f, &plan(&[])).unwrap();
    drive(&mut r, Duration::from_secs(10));
    let e = r.result.as_ref().unwrap().as_ref().unwrap_err();
    assert!(e.contains("XML"), "{e}");
}

#[test]
fn cancelamento_mata_o_processo_e_limpa() {
    let f = Fake::new("cancel", "echo 'Starting Nmap'\nexec sleep 30\n");
    let mut r = start(&f, &plan(&[])).unwrap();
    let tmp = r.temp_path().unwrap().to_path_buf();
    std::thread::sleep(Duration::from_millis(150));
    let t0 = Instant::now();
    r.cancel();
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "cancelar não pode esperar o scan"
    );
    assert_eq!(r.outcome, Some(Outcome::Cancelled));
    assert!(r.result.is_none() && !r.is_running());
    assert!(!tmp.exists());
    r.cancel(); // idempotente
}

#[test]
fn drop_mata_o_processo_e_limpa_temporarios() {
    let f = Fake::new("drop", "exec sleep 30\n");
    let r = start(&f, &plan(&[])).unwrap();
    let tmp = r.temp_path().unwrap().to_path_buf();
    drop(r);
    assert!(!tmp.exists());
}

#[test]
fn linha_gigante_e_truncada_e_muita_saida_nao_trava() {
    let f = Fake::new(
        "grande",
        "head -c 200000 /dev/zero | tr '\\0' 'a'; echo\nseq 1 20000\nexit 0",
    );
    let mut r = start(&f, &plan(&[])).unwrap();
    let lines = drive(&mut r, Duration::from_secs(20));
    assert!(
        lines[0].chars().count() <= MAX_LINE + 1 && lines[0].ends_with('…'),
        "{}",
        lines[0].len()
    );
    assert_eq!(lines.len(), 20001);
    assert_eq!(lines.last().unwrap(), "20000");
}

#[test]
fn nmap_ausente_da_erro_claro() {
    let e = Runner::start(std::ffi::OsStr::new("/nao/existe/nmap"), &plan(&[]))
        .err()
        .unwrap();
    assert!(e.contains("não foi encontrado"), "{e}");
    assert!(nscope::nmap::runner::detect(std::ffi::OsStr::new("/nao/existe/nmap")).is_err());
}

#[test]
fn deteccao_de_versao() {
    let f = Fake::new("versao", "echo 'Nmap version 7.95 ( https://nmap.org )'");
    assert_eq!(
        nscope::nmap::runner::detect(f.bin.as_os_str()).unwrap(),
        "Nmap version 7.95 ( https://nmap.org )"
    );
}
