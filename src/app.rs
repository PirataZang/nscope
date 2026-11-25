//! Estado global da aplicação: abas, seleção, edição, execução e resultados.
//! Não desenha nada (isso é `ui`) e não conhece o terminal; recebe teclas/mouse já decodificados.

use crate::i18n;
use crate::nmap::analyze::{self, Finding};
use crate::nmap::catalog::{self, Kind, Opt, Section, Values};
use crate::nmap::command::{self, Token};
use crate::nmap::knowledge::{self, Risk};
use crate::nmap::profiles::{self, PROFILES};
use crate::nmap::runner::{self, MAX_LOG_LINES, Outcome, Plan, Runner};
use crate::nmap::xml::{Port, ScanResult};
use crate::report::{self, Execution};
use crate::ui::theme::Theme;
use crate::ui::widgets::input::TextInput;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Alvo,
    Perfis,
    Configurar,
    Comando,
    Editar,
    Execucao,
    Resultados,
    Ajuda,
}

impl Tab {
    pub const ALL: [Tab; 8] = [
        Tab::Alvo,
        Tab::Perfis,
        Tab::Configurar,
        Tab::Comando,
        Tab::Editar,
        Tab::Execucao,
        Tab::Resultados,
        Tab::Ajuda,
    ];
    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// Linha da lista de opções (Alvo e Configurar).
#[derive(Clone, Copy)]
pub enum Row {
    Header(&'static str),
    Opt(&'static Opt),
    /// Item do navegador de scripts NSE: (nome, descrição, risco), é categoria?
    Nse(&'static (&'static str, &'static str, Risk), bool),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lvl {
    Ok,
    Warn,
    Err,
}

pub struct Flash {
    pub msg: String,
    pub lvl: Lvl,
    at: Instant,
}

pub struct Edit {
    pub id: &'static str,
    pub input: TextInput,
    original: String,
}

/// Edição do comando inteiro (aba Editar). `original` volta com Esc.
pub struct CmdEdit {
    pub input: TextInput,
    original: Values,
    /// Problema ao ler o texto atual (o comando mostrado é o último que foi lido sem erro).
    pub error: Option<String>,
}

pub struct Search {
    pub input: TextInput,
    pub sel: usize,
}

#[derive(Clone, PartialEq, Debug)]
pub enum RunState {
    Idle,
    Running,
    Done,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogKind {
    Normal,
    Open,
    Warn,
    Head,
}

pub struct LogLine {
    pub text: String,
    pub kind: LogKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    /// Lista de execuções da sessão (histórico).
    Runs,
    Hosts,
    Ports,
}

/// Regiões clicáveis registradas pelo desenho.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Hit {
    Tab(usize),
    Sub(usize),
    Row(usize),
    Profile(usize),
    Finding(usize),
    HelpSection(usize),
    /// Linha do histórico de execuções (Resultados).
    Exec(usize),
    EditCmd,
    Host(usize),
    Port(usize),
    Run,
    Cancel,
    Copy,
}

pub struct Env {
    pub privileged: bool,
    /// Versão do nmap, ou a mensagem de erro se não foi encontrado.
    pub nmap: Result<String, String>,
    pub program: OsString,
}

impl Env {
    pub fn detect() -> Env {
        let program = OsString::from("nmap");
        Env {
            privileged: crate::util::is_privileged(),
            nmap: runner::detect(&program),
            program,
        }
    }
}

pub struct App {
    pub env: Env,
    pub theme: Theme,
    pub values: Values,
    pub tab: Tab,
    pub sub: usize,
    cursors: [usize; 13],
    pub list_offset: [usize; 13],
    pub detail_scroll: usize,
    pub pieces_scroll: usize,
    pub edit: Option<Edit>,
    pub cmd_edit: Option<CmdEdit>,
    pub search: Option<Search>,
    pub flash: Option<Flash>,
    pub quit: bool,
    pub copy_request: Option<String>,
    pub hits: Vec<(Rect, Hit)>,
    // execução
    runner: Option<Runner>,
    pub run_state: RunState,
    pub run_command: String,
    pub run_standalone: bool,
    pub log: VecDeque<LogLine>,
    /// Linhas rolada para cima a partir do fim (0 = acompanhando).
    pub log_back: usize,
    pub run_progress: Option<runner::Progress>,
    run_elapsed: Duration,
    pub started_at: Instant,
    // resultados
    /// Resultado em exibição (o da execução escolhida no histórico).
    pub result: Option<ScanResult>,
    /// Execuções desta sessão, em memória até o usuário salvar (s em Resultados).
    pub history: Vec<Execution>,
    pub hist_i: usize,
    /// Pasta onde o terminal foi aberto: relatórios e históricos são salvos aqui.
    pub save_dir: PathBuf,
    run_when: String,
    run_outputs: Vec<PathBuf>,
    pub pane: Pane,
    pub host_i: usize,
    pub port_i: usize,
    pub only_open: bool,
}

const KEY_PROFILES: usize = 10;
const KEY_FINDINGS: usize = 11;
const KEY_HELP: usize = 12;

fn classify(text: &str, is_err: bool) -> LogKind {
    let t = text.trim_start();
    let port_open = t.split_once(' ').is_some_and(|(p, rest)| {
        p.split_once('/').is_some_and(|(n, proto)| {
            n.bytes().all(|b| b.is_ascii_digit())
                && !n.is_empty()
                && matches!(proto, "tcp" | "udp" | "sctp" | "ip")
        }) && rest.trim_start().starts_with("open")
    });
    if t.starts_with("Discovered open port") || port_open {
        LogKind::Open
    } else if is_err
        || t.starts_with("Warning")
        || t.starts_with("WARNING")
        || t.starts_with("Note:")
        || t.contains(" filtered ")
    {
        LogKind::Warn
    } else if t.starts_with("Nmap scan report")
        || t.starts_with("Starting Nmap")
        || t.starts_with("Nmap done")
    {
        LogKind::Head
    } else {
        LogKind::Normal
    }
}

/// Arquivos que o nmap vai gravar por pedido do usuário (-oN/-oX/-oG/-oS/-oA).
fn output_files(v: &Values) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = ["oN", "oX", "oG", "oS"]
        .iter()
        .map(|id| v.text(id))
        .filter(|p| !p.is_empty() && *p != "-")
        .map(PathBuf::from)
        .collect();
    let base = v.text("oA");
    if !base.is_empty() {
        out.extend(["nmap", "xml", "gnmap"].map(|e| PathBuf::from(format!("{base}.{e}"))));
    }
    out
}

impl App {
    pub fn new(env: Env) -> App {
        App {
            env,
            theme: Theme::from_env(),
            values: Values::default(),
            tab: Tab::Alvo,
            sub: 0,
            cursors: [0; 13],
            list_offset: [0; 13],
            detail_scroll: 0,
            pieces_scroll: 0,
            edit: None,
            cmd_edit: None,
            search: None,
            flash: None,
            quit: false,
            copy_request: None,
            hits: Vec::new(),
            runner: None,
            run_state: RunState::Idle,
            run_command: String::new(),
            run_standalone: false,
            log: VecDeque::new(),
            log_back: 0,
            run_progress: None,
            run_elapsed: Duration::ZERO,
            started_at: Instant::now(),
            result: None,
            history: Vec::new(),
            hist_i: 0,
            save_dir: std::env::current_dir().unwrap_or_else(|_| ".".into()),
            run_when: String::new(),
            run_outputs: Vec::new(),
            pane: Pane::Hosts,
            host_i: 0,
            port_i: 0,
            only_open: false,
        }
    }

    // ---------- consultas ----------

    pub fn findings(&self) -> Vec<Finding> {
        analyze::analyze(&self.values, self.env.privileged)
    }
    pub fn tokens(&self) -> Vec<Token> {
        command::build(&self.values)
    }
    pub fn command_text(&self) -> String {
        command::display(&self.tokens())
    }
    pub fn section(&self) -> Option<Section> {
        match self.tab {
            Tab::Alvo => Some(Section::Alvo),
            Tab::Configurar => Some(Section::CONFIG[self.sub]),
            _ => None,
        }
    }
    /// Índice da lista corrente em `cursors`/`list_offset`.
    pub fn list_key(&self) -> usize {
        match self.tab {
            Tab::Alvo => 0,
            Tab::Configurar => 1 + self.sub,
            Tab::Perfis => KEY_PROFILES,
            Tab::Ajuda => KEY_HELP,
            _ => KEY_FINDINGS,
        }
    }
    pub fn cursor(&self) -> usize {
        self.cursors[self.list_key()]
    }
    fn set_cursor(&mut self, i: usize) {
        let k = self.list_key();
        self.cursors[k] = i;
        self.detail_scroll = 0;
    }
    pub fn rows(&self) -> Vec<Row> {
        let Some(sec) = self.section() else {
            return vec![];
        };
        let mut rows: Vec<Row> = catalog::section(sec)
            .filter(|o| self.values.visible(o))
            .map(Row::Opt)
            .collect();
        if sec == Section::Scripts {
            rows.push(Row::Header("Categorias de scripts (Enter adiciona/remove)"));
            rows.extend(knowledge::NSE_CATEGORIES.iter().map(|c| Row::Nse(c, true)));
            rows.push(Row::Header("Scripts populares (Enter adiciona/remove)"));
            rows.extend(knowledge::NSE_POPULAR.iter().map(|c| Row::Nse(c, false)));
        }
        rows
    }
    pub fn selected_row(&self) -> Option<Row> {
        let rows = self.rows();
        rows.get(self.cursor().min(rows.len().saturating_sub(1)))
            .copied()
    }
    pub fn script_items(&self) -> Vec<String> {
        self.values
            .text("script")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }
    pub fn flash_active(&self) -> Option<&Flash> {
        self.flash
            .as_ref()
            .filter(|f| f.at.elapsed() < Duration::from_secs(4))
    }
    pub fn elapsed(&self) -> Duration {
        self.runner
            .as_ref()
            .map_or(self.run_elapsed, Runner::elapsed)
    }
    pub fn is_running(&self) -> bool {
        self.runner.is_some()
    }
    pub fn host_ports(&self) -> Vec<&Port> {
        let Some(h) = self.result.as_ref().and_then(|r| r.hosts.get(self.host_i)) else {
            return vec![];
        };
        h.ports
            .iter()
            .filter(|p| !self.only_open || p.is_open())
            .collect()
    }
    pub fn search_hits(&self) -> Vec<&'static Opt> {
        let Some(s) = &self.search else { return vec![] };
        let q = s.input.value().to_lowercase();
        let terms: Vec<&str> = q.split_whitespace().collect();
        catalog::all()
            .iter()
            .filter(|o| {
                let mut hay = format!("{} {} {} {}", o.label, o.flag, o.id, o.what);
                for c in &o.choices {
                    hay.push_str(&format!(" {} {}", c.label, c.flag));
                }
                let hay = hay.to_lowercase();
                terms.iter().all(|t| hay.contains(t))
            })
            .take(40)
            .collect()
    }

    // ---------- mensagens ----------

    pub fn say(&mut self, lvl: Lvl, msg: impl Into<String>) {
        self.flash = Some(Flash {
            msg: msg.into(),
            lvl,
            at: Instant::now(),
        });
    }

    // ---------- navegação ----------

    pub fn set_tab(&mut self, t: Tab) {
        self.tab = t;
        self.edit = None;
        self.cmd_edit = None;
        self.detail_scroll = 0;
    }
    fn next_tab(&mut self, d: isize) {
        let n = Tab::ALL.len() as isize;
        let i = (self.tab.index() as isize + d).rem_euclid(n) as usize;
        self.set_tab(Tab::ALL[i]);
    }

    fn move_cursor(&mut self, d: isize) {
        match self.tab {
            Tab::Alvo | Tab::Configurar => {
                let rows = self.rows();
                let mut i = self.cursor() as isize;
                loop {
                    let n = i + d;
                    if n < 0 || n >= rows.len() as isize {
                        break;
                    }
                    i = n;
                    if !matches!(rows[i as usize], Row::Header(_)) {
                        self.set_cursor(i as usize);
                        break;
                    }
                }
            }
            Tab::Perfis => {
                let n = (self.cursor() as isize + d).clamp(0, PROFILES.len() as isize - 1) as usize;
                self.set_cursor(n);
            }
            Tab::Comando => {
                let len = self.findings().len();
                let n =
                    (self.cursor() as isize + d).clamp(0, len.saturating_sub(1) as isize) as usize;
                self.set_cursor(n);
            }
            Tab::Execucao => {
                let max = self.log.len();
                self.log_back = (self.log_back as isize - d).clamp(0, max as isize) as usize;
            }
            Tab::Resultados if self.pane == Pane::Runs => {
                let n = (self.hist_i as isize + d).max(0) as usize;
                self.select_run(n);
            }
            Tab::Resultados => {
                if self.pane == Pane::Hosts {
                    let len = self.result.as_ref().map_or(0, |r| r.hosts.len());
                    self.host_i = (self.host_i as isize + d)
                        .clamp(0, len.saturating_sub(1) as isize)
                        as usize;
                    self.port_i = 0;
                } else {
                    let len = self.host_ports().len();
                    self.port_i = (self.port_i as isize + d)
                        .clamp(0, len.saturating_sub(1) as isize)
                        as usize;
                }
                self.detail_scroll = 0;
            }
            Tab::Editar => self.detail_scroll = (self.detail_scroll as isize + d).max(0) as usize,
            Tab::Ajuda => {
                let n = i18n::help().len() as isize;
                self.set_cursor((self.cursor() as isize + d).clamp(0, n - 1) as usize);
            }
        }
    }

    fn scroll_detail(&mut self, d: isize) {
        match self.tab {
            Tab::Execucao => {
                self.log_back =
                    (self.log_back as isize - d).clamp(0, self.log.len() as isize) as usize
            }
            Tab::Comando => self.pieces_scroll = (self.pieces_scroll as isize + d).max(0) as usize,
            _ => self.detail_scroll = (self.detail_scroll as isize + d).max(0) as usize,
        }
    }

    /// Salta até a opção (busca e atalhos "ir" dos avisos).
    pub fn goto_opt(&mut self, id: &str) {
        let Some(o) = catalog::get(id) else { return };
        if o.section == Section::Alvo {
            self.tab = Tab::Alvo;
        } else if let Some(i) = Section::CONFIG.iter().position(|s| *s == o.section) {
            self.tab = Tab::Configurar;
            self.sub = i;
        }
        self.edit = None;
        let found = self
            .rows()
            .iter()
            .position(|r| matches!(r, Row::Opt(x) if x.id == id));
        match found {
            Some(i) => self.set_cursor(i),
            None => {
                self.set_cursor(0);
                if let Some(c) = o.visible_if {
                    let when = catalog::get(c.id).map_or(c.id, |p| p.label);
                    self.say(
                        Lvl::Warn,
                        format!(
                            "\"{}\" só aparece quando \"{when}\" está em \"{}\".",
                            o.label, c.is
                        ),
                    );
                }
            }
        }
        if self.cursor() >= self.rows().len() {
            self.set_cursor(0);
        }
    }

    // ---------- ações sobre opções ----------

    fn activate(&mut self, dir: isize) {
        match self.selected_row() {
            Some(Row::Opt(o)) => match o.kind {
                Kind::Bool => {
                    let on = !self.values.flag(o.id);
                    self.values.set(o.id, if on { "1" } else { "" });
                }
                Kind::Choice => {
                    let cur = o
                        .choices
                        .iter()
                        .position(|c| c.id == self.values.get(o.id))
                        .unwrap_or(0) as isize;
                    let n = (cur + dir).rem_euclid(o.choices.len() as isize) as usize;
                    self.values.set(o.id, o.choices[n].id);
                }
                Kind::Text | Kind::Number => {
                    let original = self.values.get(o.id).to_string();
                    self.edit = Some(Edit {
                        id: o.id,
                        input: TextInput::new(&original),
                        original,
                    });
                }
            },
            Some(Row::Nse(item, _)) => {
                let mut items = self.script_items();
                if let Some(p) = items.iter().position(|x| x == item.0) {
                    items.remove(p);
                } else {
                    items.push(item.0.to_string());
                }
                self.values.set("script", items.join(","));
            }
            _ => {}
        }
    }

    fn clear_selected(&mut self) {
        if let Some(Row::Opt(o)) = self.selected_row() {
            self.values.reset(o.id);
            self.say(Lvl::Ok, format!("{}: voltou ao padrão.", o.label));
        }
    }

    fn apply_profile(&mut self, i: usize) {
        let Some(p) = PROFILES.get(i) else { return };
        self.values = profiles::apply(p, &self.values);
        self.say(
            Lvl::Ok,
            format!(
                "Perfil \"{}\" aplicado. Ajuste em Configurar (3) ou revise em Comando (4).",
                p.name
            ),
        );
    }

    // ---------- execução ----------

    pub fn request_run(&mut self) {
        if self.runner.is_some() {
            return self.say(Lvl::Warn, i18n::MSG_ALREADY_RUNNING);
        }
        let f = self.findings();
        if analyze::has_errors(&f) {
            let n = f
                .iter()
                .filter(|x| x.level == analyze::Level::Error)
                .count();
            self.say(
                Lvl::Err,
                format!("{n} problema(s) impedem a execução. Veja os avisos em Comando."),
            );
            self.set_tab(Tab::Comando);
            return;
        }
        if self.env.nmap.is_err() {
            return self.say(Lvl::Err, i18n::MSG_NO_NMAP);
        }
        self.start_run();
    }

    fn start_run(&mut self) {
        let plan = match Plan::from_values(&self.values) {
            Ok(p) => p,
            Err(e) => return self.say(Lvl::Err, e),
        };
        self.log.clear();
        self.log_back = 0;
        self.run_progress = None;
        self.run_command = self.command_text();
        self.run_standalone = plan.standalone;
        self.run_when = crate::util::timestamp();
        self.run_outputs = output_files(&self.values);
        self.started_at = Instant::now();
        self.set_tab(Tab::Execucao);
        match Runner::start(&self.env.program, &plan) {
            Ok(r) => {
                self.runner = Some(r);
                self.run_state = RunState::Running;
            }
            Err(e) => {
                self.push_log(&e, true);
                self.run_state = RunState::Failed(e.clone());
                self.say(Lvl::Err, e);
            }
        }
    }

    pub fn cancel_run(&mut self) {
        if let Some(r) = self.runner.as_mut() {
            r.cancel();
            self.finish_run();
        }
    }

    fn push_log(&mut self, text: &str, is_err: bool) {
        if self.log.len() >= MAX_LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(LogLine {
            text: text.to_string(),
            kind: classify(text, is_err),
        });
        if self.log_back > 0 {
            self.log_back = (self.log_back + 1).min(self.log.len());
        }
    }

    fn finish_run(&mut self) {
        let Some(mut r) = self.runner.take() else {
            return;
        };
        self.run_elapsed = r.elapsed();
        self.run_progress = r.progress.take();
        let mut result = None;
        let status = match r.outcome.take() {
            Some(Outcome::Cancelled) => {
                self.push_log("^C  Scan interrompido pelo usuário.", true);
                self.run_state = RunState::Cancelled;
                self.say(Lvl::Warn, "Scan cancelado.");
                "cancelado".to_string()
            }
            Some(Outcome::Failed(e)) => {
                self.push_log(&e, true);
                self.run_state = RunState::Failed(e.clone());
                self.say(Lvl::Err, e.clone());
                format!("falhou: {e}")
            }
            Some(Outcome::Finished { code }) => {
                self.run_state = RunState::Done;
                let ok = code == Some(0);
                let code_txt = code.map_or("?".into(), |c| c.to_string());
                match r.result.take() {
                    Some(Ok(mut res)) => {
                        // o XML traz os argumentos internos (-oX temporário, --stats-every):
                        // mostra e salva o comando como o usuário o montou
                        res.command = self.run_command.clone();
                        result = Some(res);
                        self.say(
                            if ok { Lvl::Ok } else { Lvl::Warn },
                            if ok {
                                "Concluído. Veja os Resultados (7).".to_string()
                            } else {
                                format!("O nmap terminou com código {code_txt}; os resultados parciais estão em Resultados (7).")
                            },
                        );
                    }
                    Some(Err(e)) => {
                        self.push_log(&e, true);
                        self.say(Lvl::Err, e);
                    }
                    None => self.say(
                        if ok { Lvl::Ok } else { Lvl::Warn },
                        if ok {
                            "Concluído.".to_string()
                        } else {
                            format!("O nmap terminou com código {code_txt}.")
                        },
                    ),
                }
                if ok {
                    "concluído".to_string()
                } else {
                    format!("terminou com código {code_txt}")
                }
            }
            None => return,
        };
        for p in std::mem::take(&mut self.run_outputs) {
            if p.exists() {
                crate::util::give_back(&p);
            }
        }
        self.history.push(Execution {
            when: std::mem::take(&mut self.run_when),
            command: self.run_command.clone(),
            status,
            secs: self.run_elapsed.as_secs(),
            result,
            xml: r.xml.take(),
            log: self.log.iter().map(|l| l.text.clone()).collect(),
        });
        self.select_run(self.history.len() - 1);
    }

    /// Mostra em Resultados a execução `i` do histórico.
    pub fn select_run(&mut self, i: usize) {
        self.hist_i = i.min(self.history.len().saturating_sub(1));
        self.result = self.history.get(self.hist_i).and_then(|e| e.result.clone());
        self.host_i = 0;
        self.port_i = 0;
        self.detail_scroll = 0;
        if self.pane == Pane::Ports {
            self.pane = Pane::Hosts;
        }
    }

    /// Chamado a cada tick (~100 ms): consome a saída do nmap sem bloquear.
    pub fn tick(&mut self) {
        let lines = self.runner.as_mut().map(Runner::poll).unwrap_or_default();
        for m in &lines {
            let is_err = matches!(m, runner::Msg::Err(_));
            self.push_log(m.text(), is_err);
        }
        if let Some(r) = &self.runner {
            self.run_progress = r.progress.clone();
            if !r.is_running() {
                self.finish_run();
            }
        }
        if self
            .flash
            .as_ref()
            .is_some_and(|f| f.at.elapsed() >= Duration::from_secs(4))
        {
            self.flash = None;
        }
    }

    fn save_report(&mut self) {
        if self.history.is_empty() {
            return self.say(Lvl::Warn, "Ainda não há execuções para salvar.");
        }
        let n = self.history.len();
        match report::save_history(&self.history, &self.save_dir, &crate::util::timestamp()) {
            Ok(p) => self.say(
                Lvl::Ok,
                format!(
                    "Histórico salvo ({n} {}) em {}",
                    if n == 1 { "execução" } else { "execuções" },
                    p.display()
                ),
            ),
            Err(e) => self.say(
                Lvl::Err,
                format!("Não foi possível salvar o histórico: {e}"),
            ),
        }
    }

    pub fn quit_now(&mut self) {
        if let Some(r) = self.runner.as_mut() {
            r.cancel();
        }
        self.runner = None;
        self.quit = true;
    }

    /// Carrega um XML já existente (nscope --open).
    pub fn open_result(&mut self, r: ScanResult) {
        self.history.push(Execution {
            when: crate::util::timestamp(),
            command: r.command.clone(),
            status: "aberto de um arquivo XML".into(),
            secs: r.duration_secs.unwrap_or(0.0) as u64,
            result: Some(r),
            xml: None,
            log: Vec::new(),
        });
        self.select_run(self.history.len() - 1);
        self.set_tab(Tab::Resultados);
    }

    // ---------- teclado ----------

    pub fn on_key(&mut self, k: KeyEvent) {
        if k.kind == KeyEventKind::Release {
            return;
        }
        // Vários terminais (ex.: o padrão do Kali) mandam ^H no Backspace; o crossterm entrega Ctrl+H.
        let k = if k.code == KeyCode::Char('h') && k.modifiers == KeyModifiers::CONTROL {
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE)
        } else {
            k
        };
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            return self.quit_now();
        }
        if self.search.is_some() {
            return self.search_key(k);
        }
        if self.edit.is_some() {
            return self.edit_key(k);
        }
        if self.cmd_edit.is_some() {
            return self.cmd_edit_key(k);
        }
        let shift = k.modifiers.contains(KeyModifiers::SHIFT);
        match k.code {
            KeyCode::Char('q') => return self.quit_now(),
            KeyCode::Tab => return self.next_tab(1),
            KeyCode::BackTab => return self.next_tab(-1),
            KeyCode::Char(c @ '1'..='8') => {
                return self.set_tab(Tab::ALL[c as usize - '1' as usize]);
            }
            KeyCode::Char('/') => {
                self.search = Some(Search {
                    input: TextInput::default(),
                    sel: 0,
                });
                return;
            }
            KeyCode::Char('?') => return self.set_tab(Tab::Ajuda),
            KeyCode::Char('r') => return self.request_run(),
            KeyCode::Char('c') => return self.cancel_run(),
            KeyCode::Char('y') => {
                self.copy_request = Some(self.command_text());
                return self.say(Lvl::Ok, i18n::MSG_COPIED);
            }
            KeyCode::Char('o') if self.tab == Tab::Resultados => {
                self.only_open = !self.only_open;
                self.port_i = 0;
                return;
            }
            KeyCode::Char('s') if self.tab == Tab::Resultados => return self.save_report(),
            KeyCode::Down | KeyCode::Char('j') => return self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => return self.move_cursor(-1),
            KeyCode::PageDown => return self.scroll_detail(8),
            KeyCode::PageUp => return self.scroll_detail(-8),
            KeyCode::End if self.tab == Tab::Execucao => {
                self.log_back = 0;
                return;
            }
            _ => {}
        }
        let sub_move = |d: isize, s: &mut App| {
            let n = Section::CONFIG.len() as isize;
            s.sub = (s.sub as isize + d).rem_euclid(n) as usize;
            s.detail_scroll = 0;
        };
        match (self.tab, k.code) {
            (Tab::Configurar, KeyCode::Right | KeyCode::Char('l' | ']')) => sub_move(1, self),
            (Tab::Configurar, KeyCode::Left | KeyCode::Char('h' | '[')) => sub_move(-1, self),
            (Tab::Alvo | Tab::Configurar, KeyCode::Enter | KeyCode::Char(' ')) => {
                self.activate(if shift { -1 } else { 1 })
            }
            (Tab::Alvo | Tab::Configurar, KeyCode::Char('-')) => self.activate(-1),
            (Tab::Alvo | Tab::Configurar, KeyCode::Delete | KeyCode::Backspace) => {
                self.clear_selected()
            }
            (Tab::Perfis, KeyCode::Enter | KeyCode::Char(' ')) => self.apply_profile(self.cursor()),
            (Tab::Editar, KeyCode::Enter | KeyCode::Char('e')) => self.start_cmd_edit(),
            (Tab::Comando, KeyCode::Enter | KeyCode::Char('g')) => {
                if let Some(id) = self.findings().get(self.cursor()).and_then(|f| f.opt) {
                    self.goto_opt(id);
                }
            }
            (Tab::Resultados, KeyCode::Right | KeyCode::Char('l' | ']')) => {
                self.pane = if self.pane == Pane::Runs {
                    Pane::Hosts
                } else {
                    Pane::Ports
                }
            }
            (Tab::Resultados, KeyCode::Left | KeyCode::Char('h' | '[')) => {
                self.pane = if self.pane == Pane::Ports || self.history.is_empty() {
                    Pane::Hosts
                } else {
                    Pane::Runs
                }
            }
            _ => {}
        }
    }

    fn edit_key(&mut self, k: KeyEvent) {
        let Some(e) = self.edit.as_mut() else { return };
        match k.code {
            KeyCode::Enter => self.edit = None,
            KeyCode::Esc => {
                let (id, orig) = (e.id, e.original.clone());
                self.values.set(id, orig);
                self.edit = None;
            }
            _ => {
                if e.input.handle(k) {
                    let (id, v) = (e.id, e.input.value().to_string());
                    self.values.set(id, v); // o comando atualiza enquanto digita
                }
            }
        }
    }

    /// Abre o comando atual para edição livre (aba Editar).
    pub fn start_cmd_edit(&mut self) {
        self.cmd_edit = Some(CmdEdit {
            input: TextInput::new(&self.command_text()),
            original: self.values.clone(),
            error: None,
        });
    }

    fn cmd_edit_key(&mut self, k: KeyEvent) {
        let Some(e) = self.cmd_edit.as_mut() else {
            return;
        };
        match k.code {
            KeyCode::Esc => {
                self.values = e.original.clone();
                self.cmd_edit = None;
                self.say(
                    Lvl::Warn,
                    "Edição desfeita: o comando voltou ao que era antes.",
                );
            }
            KeyCode::Enter if e.error.is_some() => {
                self.say(
                    Lvl::Err,
                    "Corrija o comando (veja o problema acima) ou use Esc para desfazer.",
                );
            }
            KeyCode::Enter => {
                self.cmd_edit = None;
                self.say(
                    Lvl::Ok,
                    "Comando aplicado. Todas as abas já mostram as novas opções.",
                );
            }
            KeyCode::Up => self.scroll_detail(-1),
            KeyCode::Down => self.scroll_detail(1),
            KeyCode::PageUp => self.scroll_detail(-8),
            KeyCode::PageDown => self.scroll_detail(8),
            _ => {
                if e.input.handle(k) {
                    match command::parse(e.input.value()) {
                        Ok(v) => {
                            e.error = None;
                            self.values = v; // o resto da ferramenta acompanha enquanto digita
                        }
                        Err(m) => e.error = Some(m),
                    }
                }
            }
        }
    }

    fn search_key(&mut self, k: KeyEvent) {
        let n = self.search_hits().len();
        let Some(s) = self.search.as_mut() else {
            return;
        };
        match k.code {
            KeyCode::Esc => self.search = None,
            KeyCode::Down => s.sel = (s.sel + 1).min(n.saturating_sub(1)),
            KeyCode::Up => s.sel = s.sel.saturating_sub(1),
            KeyCode::Enter => {
                let sel = s.sel;
                let hit = self.search_hits().get(sel).map(|o| o.id);
                self.search = None;
                if let Some(id) = hit {
                    self.goto_opt(id);
                }
            }
            _ => {
                if s.input.handle(k) {
                    s.sel = 0;
                }
            }
        }
    }

    // ---------- mouse ----------

    pub fn on_mouse(&mut self, m: MouseEvent) {
        if self.search.is_some() || self.edit.is_some() || self.cmd_edit.is_some() {
            return;
        }
        match m.kind {
            MouseEventKind::ScrollDown => self.move_cursor(1),
            MouseEventKind::ScrollUp => self.move_cursor(-1),
            MouseEventKind::Down(MouseButton::Left) => {
                let hit = self
                    .hits
                    .iter()
                    .rev()
                    .find(|(r, _)| {
                        m.column >= r.x
                            && m.column < r.x + r.width
                            && m.row >= r.y
                            && m.row < r.y + r.height
                    })
                    .map(|(_, h)| *h);
                match hit {
                    Some(Hit::Tab(i)) => self.set_tab(Tab::ALL[i.min(Tab::ALL.len() - 1)]),
                    Some(Hit::HelpSection(i)) => self.set_cursor(i),
                    Some(Hit::EditCmd) => self.start_cmd_edit(),
                    Some(Hit::Sub(i)) => {
                        self.sub = i.min(Section::CONFIG.len() - 1);
                        self.detail_scroll = 0;
                    }
                    Some(Hit::Row(i)) => {
                        if !matches!(self.rows().get(i), Some(Row::Header(_)) | None) {
                            self.set_cursor(i);
                            self.activate(1);
                        }
                    }
                    Some(Hit::Profile(i)) => {
                        if self.cursor() == i {
                            self.apply_profile(i)
                        } else {
                            self.set_cursor(i)
                        }
                    }
                    Some(Hit::Finding(i)) => self.set_cursor(i),
                    Some(Hit::Exec(i)) => {
                        self.pane = Pane::Runs;
                        self.select_run(i);
                    }
                    Some(Hit::Host(i)) => {
                        self.pane = Pane::Hosts;
                        self.host_i = i;
                        self.port_i = 0;
                    }
                    Some(Hit::Port(i)) => {
                        self.pane = Pane::Ports;
                        self.port_i = i;
                    }
                    Some(Hit::Run) => self.request_run(),
                    Some(Hit::Cancel) => self.cancel_run(),
                    Some(Hit::Copy) => {
                        self.copy_request = Some(self.command_text());
                        self.say(Lvl::Ok, i18n::MSG_COPIED);
                    }
                    None => {}
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn app() -> App {
        let mut a = App::new(Env {
            privileged: false,
            nmap: Ok("Nmap version 7.95".into()),
            program: "nmap".into(),
        });
        a.theme = Theme { color: true };
        a
    }
    fn key(a: &mut App, c: KeyCode) {
        a.on_key(KeyEvent::new(c, KeyModifiers::NONE));
    }
    fn typ(a: &mut App, s: &str) {
        for c in s.chars() {
            key(a, KeyCode::Char(c));
        }
    }

    #[test]
    fn navegacao_entre_abas() {
        let mut a = app();
        key(&mut a, KeyCode::Tab);
        assert_eq!(a.tab, Tab::Perfis);
        a.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(a.tab, Tab::Alvo);
        key(&mut a, KeyCode::Char('6'));
        assert_eq!(a.tab, Tab::Execucao);
        key(&mut a, KeyCode::Char('?'));
        assert_eq!(a.tab, Tab::Ajuda);
        a.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        key(&mut a, KeyCode::Char('3'));
        key(&mut a, KeyCode::Right);
        assert_eq!(a.sub, 1);
        key(&mut a, KeyCode::Char('['));
        key(&mut a, KeyCode::Char('['));
        assert_eq!(a.sub, 8, "sub-abas dão a volta");
    }

    #[test]
    fn ligar_opcao_e_editar_texto_com_esc_restaurando() {
        let mut a = app();
        key(&mut a, KeyCode::Char('3')); // Configurar > Descoberta
        key(&mut a, KeyCode::Enter); // -Pn
        assert!(a.values.flag("Pn"));
        assert_eq!(a.command_text(), "nmap -Pn scanme.nmap.org");
        key(&mut a, KeyCode::Down);
        key(&mut a, KeyCode::Enter); // -PS (texto)
        assert!(a.edit.is_some());
        typ(&mut a, "22,80");
        assert_eq!(
            a.command_text(),
            "nmap -Pn -PS22,80 scanme.nmap.org",
            "atualiza enquanto digita"
        );
        key(&mut a, KeyCode::Esc);
        assert!(a.edit.is_none() && a.values.text("PS").is_empty());
        key(&mut a, KeyCode::Enter);
        typ(&mut a, "443");
        key(&mut a, KeyCode::Enter);
        assert_eq!(a.values.text("PS"), "443");
        key(&mut a, KeyCode::Delete);
        assert_eq!(a.values.text("PS"), "");
        assert!(a.flash_active().is_some());
    }

    #[test]
    fn escolha_cicla_para_frente_e_para_tras() {
        let mut a = app();
        key(&mut a, KeyCode::Char('3'));
        key(&mut a, KeyCode::Right); // Técnica
        key(&mut a, KeyCode::Enter);
        assert_eq!(a.values.get("tec"), "sL");
        key(&mut a, KeyCode::Char('-'));
        key(&mut a, KeyCode::Char('-'));
        assert_eq!(a.values.get("tec"), "b", "volta dando a volta");
        assert!(a.command_text().contains("-b <servidor ftp relay>"));
    }

    #[test]
    fn campo_condicional_aparece_so_com_a_tecnica() {
        let mut a = app();
        a.set_tab(Tab::Configurar);
        a.sub = 1;
        let n0 = a.rows().len();
        a.values.set("tec", "sI");
        assert_eq!(a.rows().len(), n0 + 1);
    }

    #[test]
    fn perfil_aplica_mantendo_alvo() {
        let mut a = app();
        a.values.set("targets", "192.0.2.7");
        key(&mut a, KeyCode::Char('2'));
        for _ in 0..3 {
            key(&mut a, KeyCode::Down);
        }
        key(&mut a, KeyCode::Enter);
        assert_eq!(a.command_text(), "nmap -F -T4 192.0.2.7");
        assert_eq!(
            profiles::active(&a.values),
            Some(3),
            "o perfil aplicado fica marcado"
        );
        a.values.set("sV", "1");
        assert_eq!(
            profiles::active(&a.values),
            None,
            "mudou uma opção: sai a marca"
        );
    }

    #[test]
    fn busca_e_salto() {
        let mut a = app();
        key(&mut a, KeyCode::Char('/'));
        typ(&mut a, "--ttl");
        assert!(a.search_hits().iter().any(|o| o.id == "ttl"));
        key(&mut a, KeyCode::Enter);
        assert_eq!(
            (a.tab, a.section()),
            (Tab::Configurar, Some(Section::Evasao))
        );
        assert!(matches!(a.selected_row(), Some(Row::Opt(o)) if o.id == "ttl"));
        // opção condicional oculta: salta para a seção e avisa
        a.goto_opt("zombie");
        assert!(a.flash_active().unwrap().msg.contains("só aparece"));
    }

    #[test]
    fn navegador_de_scripts_liga_e_desliga() {
        let mut a = app();
        a.goto_opt("script");
        let i = a
            .rows()
            .iter()
            .position(|r| matches!(r, Row::Nse(x, _) if x.0 == "http-title"))
            .unwrap();
        a.set_cursor(i);
        key(&mut a, KeyCode::Char(' '));
        a.goto_opt("script");
        let j = a
            .rows()
            .iter()
            .position(|r| matches!(r, Row::Nse(x, _) if x.0 == "safe"))
            .unwrap();
        a.set_cursor(j);
        key(&mut a, KeyCode::Enter);
        assert_eq!(a.values.get("script"), "http-title,safe");
        key(&mut a, KeyCode::Enter);
        assert_eq!(a.values.get("script"), "http-title");
        // setas pulam os cabeçalhos
        a.set_cursor(
            a.rows()
                .iter()
                .position(|r| matches!(r, Row::Header(_)))
                .unwrap()
                - 1,
        );
        key(&mut a, KeyCode::Down);
        assert!(matches!(a.selected_row(), Some(Row::Nse(..))));
    }

    #[test]
    fn executar_com_erro_vai_para_comando() {
        let mut a = app();
        a.values.set("tec", "sS"); // sem admin
        key(&mut a, KeyCode::Char('r'));
        assert_eq!(a.tab, Tab::Comando);
        assert_eq!(a.flash_active().unwrap().lvl, Lvl::Err);
        assert!(!a.is_running());
        // Enter no aviso salta para a opção responsável
        key(&mut a, KeyCode::Enter);
        assert_eq!(
            (a.tab, a.section()),
            (Tab::Configurar, Some(Section::Tecnica))
        );
    }

    #[test]
    fn sem_nmap_a_interface_funciona_mas_nao_executa() {
        let mut a = app();
        a.env.nmap = Err("nmap não encontrado".into());
        key(&mut a, KeyCode::Char('r'));
        assert!(a.flash_active().unwrap().msg.contains("não está instalado"));
        assert!(!a.is_running());
    }

    #[test]
    fn copiar_pede_osc52() {
        let mut a = app();
        key(&mut a, KeyCode::Char('y'));
        assert_eq!(a.copy_request.as_deref(), Some("nmap scanme.nmap.org"));
    }

    #[test]
    fn sair_com_q_e_ctrl_c_mas_q_dentro_da_edicao_e_texto() {
        let mut a = app();
        key(&mut a, KeyCode::Enter); // editar alvos
        key(&mut a, KeyCode::Char('q'));
        assert!(!a.quit && a.values.text("targets").ends_with('q'));
        a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(a.quit);
        let mut b = app();
        key(&mut b, KeyCode::Char('q'));
        assert!(b.quit);
    }

    #[test]
    fn backspace_que_chega_como_ctrl_h_apaga_a_letra() {
        let mut a = app();
        key(&mut a, KeyCode::Enter); // editar alvos
        typ(&mut a, "xy");
        a.on_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL));
        assert!(a.values.text("targets").ends_with('x'));
        key(&mut a, KeyCode::Enter);
        a.set_tab(Tab::Configurar);
        a.on_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL));
        assert_eq!(
            a.sub, 0,
            "não pode trocar de sub-aba como se fosse a tecla h"
        );
    }

    #[test]
    fn editar_o_comando_inteiro_atualiza_as_opcoes_e_esc_desfaz() {
        let mut a = app();
        key(&mut a, KeyCode::Char('5'));
        assert_eq!(a.tab, Tab::Editar);
        key(&mut a, KeyCode::Enter);
        assert_eq!(
            a.cmd_edit.as_ref().unwrap().input.value(),
            "nmap scanme.nmap.org"
        );
        typ(&mut a, " -sV -p 22");
        assert!(a.values.flag("sV") && a.command_text().contains("-p 22"));
        typ(&mut a, ";");
        assert!(a.cmd_edit.as_ref().unwrap().error.is_some());
        key(&mut a, KeyCode::Enter); // com erro, continua editando
        assert!(a.cmd_edit.is_some());
        key(&mut a, KeyCode::Backspace);
        key(&mut a, KeyCode::Enter);
        assert!(a.cmd_edit.is_none() && a.values.flag("sV"));
        key(&mut a, KeyCode::Enter);
        typ(&mut a, " -O");
        key(&mut a, KeyCode::Esc);
        assert_eq!(a.command_text(), "nmap -p 22 -sV scanme.nmap.org");
    }

    #[test]
    fn resultados_filtro_so_abertas() {
        let mut a = app();
        a.open_result(crate::nmap::xml::parse(include_str!("../fixtures/basico.xml")).unwrap());
        assert_eq!(a.tab, Tab::Resultados);
        assert_eq!(a.host_ports().len(), 4);
        key(&mut a, KeyCode::Char('o'));
        assert_eq!(a.host_ports().len(), 3); // open + open|filtered
        key(&mut a, KeyCode::Right);
        assert_eq!(a.pane, Pane::Ports);
        key(&mut a, KeyCode::Down);
        assert_eq!(a.port_i, 1);
        key(&mut a, KeyCode::Left);
        key(&mut a, KeyCode::Down);
        assert_eq!((a.host_i, a.port_i), (1, 0));
    }

    #[test]
    fn classificacao_do_log() {
        assert_eq!(
            classify("Discovered open port 22/tcp on 192.0.2.1", false),
            LogKind::Open
        );
        assert_eq!(classify("22/tcp   open  ssh", false), LogKind::Open);
        assert_eq!(classify("3306/tcp filtered mysql", false), LogKind::Warn);
        assert_eq!(classify("Nmap scan report for x", false), LogKind::Head);
        assert_eq!(classify("qualquer", true), LogKind::Warn);
        assert_eq!(classify("qualquer", false), LogKind::Normal);
    }
}
