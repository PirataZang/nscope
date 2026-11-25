//! Execução do nmap: processo (sem shell), duas threads de leitura, progresso, cancelamento e
//! diretório temporário privado. O loop principal consome as mensagens a cada tick, sem bloquear.

use super::catalog::Values;
use super::command;
use super::xml::{self, ScanResult};
use crate::util::clean;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Tamanho máximo de uma linha lida do processo (o resto é descartado).
pub const MAX_LINE: usize = 8 * 1024;
/// Linhas de log mantidas em memória pela interface.
pub const MAX_LOG_LINES: usize = 5000;
const DRAIN_PER_POLL: usize = 1000;
/// Espera máxima pelo fim das threads depois que o processo saiu.
const GRACE: Duration = Duration::from_secs(2);

// ---------- diretório temporário privado ----------

/// Diretório 0700 com nome único (PID + nanossegundos); falha se já existir; removido no `Drop`.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn create() -> std::io::Result<TempDir> {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let mut last = None;
        for _ in 0..8 {
            // PID + nanossegundos (+ contador, pois relógios têm resolução grosseira)
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("nscope-{}-{nanos}-{seq}", std::process::id()));
            let mut b = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            match b.create(&path) {
                // sem `recursive`: falha se já existir, e nunca reaproveita um diretório alheio
                Ok(()) => return Ok(TempDir { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            std::io::Error::other("não foi possível criar o diretório temporário")
        }))
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------- progresso ----------

#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub percent: f32,
    pub remaining: Option<String>,
}

/// Extrai de linhas como `... About 23.40% done; ETC: 14:03 (0:00:12 remaining)`.
pub fn parse_progress(line: &str) -> Option<Progress> {
    let rest = &line[line.find("About ")? + 6..];
    let end = rest.find('%')?;
    let percent: f32 = rest[..end]
        .trim()
        .parse()
        .ok()
        .filter(|p: &f32| (0.0..=100.0).contains(p))?;
    if !rest[end..].starts_with("% done") {
        return None;
    }
    let remaining = rest.find('(').and_then(|i| {
        rest[i + 1..]
            .find(" remaining")
            .map(|j| rest[i + 1..i + 1 + j].to_string())
    });
    Some(Progress { percent, remaining })
}

// ---------- plano de execução ----------

#[derive(Debug, Clone)]
pub struct Plan {
    /// Argumentos montados pelo usuário (sem os internos).
    pub args: Vec<String>,
    /// XML escolhido pelo usuário (-oX ou -oA); `None` = o nscope usa um temporário.
    pub user_xml: Option<PathBuf>,
    /// Só mostra informação (-V, -h...): sem XML, sem progresso.
    pub standalone: bool,
    pub user_stats: bool,
}

impl Plan {
    pub fn from_values(v: &Values) -> Result<Plan, String> {
        let tokens = command::build(v);
        let args = command::argv(&tokens)
            .ok_or("Faltam valores obrigatórios no comando (veja a aba Comando).")?;
        let standalone = super::catalog::all()
            .iter()
            .any(|o| o.standalone && v.on(o.id));
        let user_xml = match (v.text("oX"), v.text("oA")) {
            ("-", _) => None,
            ("", "") => None,
            ("", base) => Some(PathBuf::from(format!("{base}.xml"))),
            (x, _) => Some(PathBuf::from(x)),
        };
        Ok(Plan {
            args,
            user_xml,
            standalone,
            user_stats: v.on("statsevery"),
        })
    }
}

// ---------- processo ----------

#[derive(Debug)]
pub enum Msg {
    Out(String),
    Err(String),
}

impl Msg {
    pub fn text(&self) -> &str {
        match self {
            Msg::Out(l) | Msg::Err(l) => l,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Finished { code: Option<i32> },
    Cancelled,
    Failed(String),
}

pub struct Runner {
    child: Option<Child>,
    rx: Option<Receiver<Msg>>,
    readers: Vec<JoinHandle<()>>,
    tmp: Option<TempDir>,
    xml_path: Option<PathBuf>,
    standalone: bool,
    exited_at: Option<(Instant, Option<i32>)>,
    pub started: Instant,
    pub progress: Option<Progress>,
    pub outcome: Option<Outcome>,
    /// Resultado do XML (só depois de terminar, sem standalone): `Err` = mensagem para o usuário.
    pub result: Option<Result<ScanResult, String>>,
    /// XML bruto do nmap (guardado para o histórico salvo poder ser reaberto com --open).
    pub xml: Option<String>,
}

fn reader<R: Read>(r: R, tx: SyncSender<Msg>, is_err: bool) {
    let mut br = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = match (&mut br).take(MAX_LINE as u64).read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let truncated = !buf.ends_with(b"\n") && n >= MAX_LINE;
        if truncated {
            // descarta o resto da linha gigante sem guardar na memória
            let mut sink = Vec::new();
            loop {
                sink.clear();
                match (&mut br).take(MAX_LINE as u64).read_until(b'\n', &mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if sink.ends_with(b"\n") => break,
                    Ok(_) => {}
                }
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let mut line = clean(text.trim_end_matches(['\n', '\r']));
        if truncated {
            line.push('…');
        }
        let msg = if is_err {
            Msg::Err(line)
        } else {
            Msg::Out(line)
        };
        if tx.send(msg).is_err() {
            break;
        }
    }
}

impl Runner {
    /// Inicia o nmap. `program` normalmente é `nmap` (resolvido pelo PATH); os testes passam um falso.
    pub fn start(program: &OsStr, plan: &Plan) -> Result<Runner, String> {
        let mut args: Vec<String> = Vec::new();
        let mut tmp = None;
        let mut xml_path = plan.user_xml.clone();
        if !plan.standalone {
            if !plan.user_stats {
                args.extend(["--stats-every".into(), "1s".into()]);
            }
            if xml_path.is_none() {
                let t = TempDir::create().map_err(|e| {
                    format!("Não foi possível criar o diretório temporário privado: {e}.")
                })?;
                let p = t.path().join("scan.xml");
                args.extend(["-oX".into(), p.to_string_lossy().into_owned()]);
                xml_path = Some(p);
                tmp = Some(t);
            }
        }
        args.extend(plan.args.iter().cloned());

        let mut child = Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    "O nmap não foi encontrado no PATH. Veja a aba Ajuda para instalar.".to_string()
                }
                _ => format!("Não foi possível iniciar o nmap: {e}."),
            })?;
        let (tx, rx) = sync_channel::<Msg>(4096);
        let mut readers = Vec::new();
        if let Some(o) = child.stdout.take() {
            let tx = tx.clone();
            readers.push(std::thread::spawn(move || reader(o, tx, false)));
        }
        if let Some(e) = child.stderr.take() {
            let tx = tx.clone();
            readers.push(std::thread::spawn(move || reader(e, tx, true)));
        }
        drop(tx);
        Ok(Runner {
            child: Some(child),
            rx: Some(rx),
            readers,
            tmp,
            xml_path,
            standalone: plan.standalone,
            exited_at: None,
            started: Instant::now(),
            progress: None,
            outcome: None,
            result: None,
            xml: None,
        })
    }

    pub fn is_running(&self) -> bool {
        self.outcome.is_none()
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Chamado a cada tick (~100 ms): devolve as linhas novas e finaliza quando o processo termina.
    pub fn poll(&mut self) -> Vec<Msg> {
        let mut lines = Vec::new();
        let Some(rx) = &self.rx else { return lines };
        let mut disconnected = false;
        while lines.len() < DRAIN_PER_POLL {
            match rx.try_recv() {
                Ok(m) => {
                    if let Some(p) = parse_progress(m.text()) {
                        self.progress = Some(p);
                    }
                    lines.push(m);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if self.exited_at.is_none()
            && let Some(c) = self.child.as_mut()
        {
            match c.try_wait() {
                Ok(Some(st)) => self.exited_at = Some((Instant::now(), st.code())),
                Ok(None) => {}
                Err(e) => self.finish(
                    Outcome::Failed(format!("Erro ao acompanhar o nmap: {e}.")),
                    &mut lines,
                    false,
                ),
            }
        }
        if let Some((at, code)) = self.exited_at
            && self.outcome.is_none()
            && (disconnected || at.elapsed() > GRACE)
        {
            // sem `disconnected`, algum neto ainda segura o pipe: não juntamos as threads (evita travar)
            self.finish(Outcome::Finished { code }, &mut lines, disconnected);
        }
        lines
    }

    fn finish(&mut self, outcome: Outcome, tail: &mut Vec<Msg>, join: bool) {
        // esgota o canal: as últimas linhas chegam ao chamador antes do fim
        if let Some(rx) = self.rx.take() {
            while let Ok(m) = rx.try_recv() {
                if let Some(p) = parse_progress(m.text()) {
                    self.progress = Some(p);
                }
                tail.push(m);
            }
        }
        for h in self.readers.drain(..) {
            if join {
                let _ = h.join();
            }
        }
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if matches!(outcome, Outcome::Finished { .. }) && !self.standalone {
            self.result = self.xml_path.as_deref().map(|p| {
                if p.exists() {
                    xml::read_file(p)
                } else {
                    Err("O nmap terminou sem gerar o arquivo XML de resultados.".to_string())
                }
            });
            if matches!(self.result, Some(Ok(_))) {
                self.xml = self
                    .xml_path
                    .as_deref()
                    .and_then(|p| std::fs::read_to_string(p).ok());
            }
        }
        if matches!(outcome, Outcome::Cancelled) {
            self.progress = None;
        }
        self.tmp = None; // remove o diretório temporário
        self.outcome = Some(outcome);
    }

    /// Cancela: kill + wait, marca como cancelado e limpa os temporários.
    pub fn cancel(&mut self) {
        if self.outcome.is_some() {
            return;
        }
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // fecha o canal antes de juntar: leitores bloqueados em `send` saem com erro
        self.rx = None;
        // não junta as threads: um neto do nmap segurando o pipe travaria a interface; elas saem sozinhas
        self.finish(Outcome::Cancelled, &mut Vec::new(), false);
    }

    /// Caminho do diretório temporário, se houver (para testes).
    pub fn temp_path(&self) -> Option<&Path> {
        self.tmp.as_ref().map(TempDir::path)
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // `tmp` é removido pelo Drop do TempDir logo em seguida
    }
}

/// Detecta o nmap no PATH (`nmap --version`). `Err` traz a mensagem para o usuário.
pub fn detect(program: &OsStr) -> Result<String, String> {
    let out = Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "nmap não encontrado no PATH".to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next().unwrap_or("").trim();
    if out.status.success() && !first.is_empty() {
        Ok(clean(first))
    } else {
        Err("o comando nmap não respondeu a --version".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progresso() {
        let p = parse_progress(
            "SYN Stealth Scan Timing: About 23.40% done; ETC: 14:03 (0:00:12 remaining)",
        )
        .unwrap();
        assert_eq!(
            p,
            Progress {
                percent: 23.4,
                remaining: Some("0:00:12".into())
            }
        );
        assert_eq!(
            parse_progress(
                "Service scan Timing: About 100.00% done; ETC: 14:03 (0:00:00 remaining)"
            )
            .unwrap()
            .percent,
            100.0
        );
        assert_eq!(parse_progress("About 5% done").unwrap().remaining, None);
        for bad in [
            "",
            "Starting Nmap",
            "About x% done",
            "About 120.0% done",
            "About 10 percent",
            "About -3% done",
            "About % done",
        ] {
            assert!(parse_progress(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn tempdir_privado_unico_e_removido() {
        let p;
        {
            let t = TempDir::create().unwrap();
            p = t.path().to_path_buf();
            assert!(p.is_dir());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            let t2 = TempDir::create().unwrap();
            assert_ne!(t.path(), t2.path());
            // criação sobre um diretório existente falha
            assert!(std::fs::DirBuilder::new().create(t.path()).is_err());
        }
        assert!(!p.exists());
    }

    #[test]
    fn plano_define_xml_do_usuario() {
        let mut v = Values::default();
        assert!(Plan::from_values(&v).unwrap().user_xml.is_none());
        v.set("oA", "rel");
        assert_eq!(
            Plan::from_values(&v).unwrap().user_xml,
            Some(PathBuf::from("rel.xml"))
        );
        v.set("oX", "x.xml");
        assert_eq!(
            Plan::from_values(&v).unwrap().user_xml,
            Some(PathBuf::from("x.xml"))
        );
        v.set("oX", "-");
        v.set("oA", "");
        assert!(Plan::from_values(&v).unwrap().user_xml.is_none());
        v.set("V", "1");
        assert!(Plan::from_values(&v).unwrap().standalone);
        v.set("tec", "sI");
        assert!(Plan::from_values(&v).is_err());
    }
}
