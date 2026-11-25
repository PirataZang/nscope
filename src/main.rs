use nscope::app::{App, Env};
use nscope::nmap::{catalog::Values, command, profiles, xml};
use nscope::{ui, util};
use ratatui::crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event};
use ratatui::crossterm::execute;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

const HELP: &str = "nscope — TUI em português para montar, explicar e executar o nmap

USO:
  nscope                         abre a interface
  nscope --open scan.xml         abre direto nos Resultados de um XML do nmap
  nscope --print-command [--profile NOME] [--target ALVO]
                                 imprime o comando montado (sem executar)
  nscope --print-catalog         imprime a referência de opções (Markdown)
  nscope --sem-sudo              abre sem pedir a senha do sudo (Linux/macOS)
  nscope --version | --help

Use apenas em sistemas seus ou com autorização por escrito.";

enum Cli {
    Tui(Option<PathBuf>),
    Print {
        profile: Option<String>,
        target: Option<String>,
    },
    Exit(String, i32),
}

fn parse_args(args: &[String]) -> Cli {
    let mut it = args.iter();
    let (mut open, mut print, mut profile, mut target) = (None, false, None, None);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--version" | "-V" => {
                return Cli::Exit(format!("nscope {}", env!("CARGO_PKG_VERSION")), 0);
            }
            "--help" | "-h" => return Cli::Exit(HELP.into(), 0),
            "--open" => match it.next() {
                Some(p) => open = Some(PathBuf::from(p)),
                None => return Cli::Exit("--open precisa do caminho de um arquivo XML.".into(), 2),
            },
            "--print-command" => print = true,
            "--sem-sudo" => {} // tratado em elevate()
            "--print-catalog" => return Cli::Exit(nscope::nmap::catalog::to_markdown(), 0),
            "--profile" => profile = it.next().cloned(),
            "--target" => target = it.next().cloned(),
            other => return Cli::Exit(format!("Opção desconhecida: {other}\n\n{HELP}"), 2),
        }
    }
    if print {
        Cli::Print { profile, target }
    } else {
        Cli::Tui(open)
    }
}

fn print_command(profile: Option<String>, target: Option<String>) -> Result<String, String> {
    let mut v = Values::default();
    if let Some(t) = target {
        v.set("targets", t);
    }
    if let Some(name) = profile {
        let p = profiles::find(&name).ok_or_else(|| format!("Perfil não encontrado: {name}"))?;
        v = profiles::apply(p, &v);
    }
    let f = nscope::nmap::analyze::analyze(&v, true);
    if let Some(e) = f
        .iter()
        .find(|x| x.level == nscope::nmap::analyze::Level::Error)
    {
        return Err(e.msg.clone());
    }
    Ok(command::display(&command::build(&v)))
}

/// Em Linux/macOS, reabre o nscope com sudo para liberar SYN, UDP e detecção de SO.
/// Só retorna se não der para elevar (sem sudo, senha errada): aí segue como usuário comum.
#[cfg(unix)]
fn elevate(args: &[String]) {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if !interactive || args.iter().any(|a| a == "--sem-sudo") || util::is_privileged() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    eprintln!("nscope: pedindo sudo para os scans que exigem root (use --sem-sudo para pular).");
    if !Command::new("sudo")
        .arg("-v")
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("nscope: sem sudo, seguindo como usuário comum.");
        return;
    }
    // --sem-sudo no filho evita laço se ele ainda não se enxergar como root.
    let err = Command::new("sudo")
        .arg("--")
        .arg(exe)
        .args(args)
        .arg("--sem-sudo")
        .exec();
    eprintln!("nscope: não deu para reabrir com sudo ({err}), seguindo como usuário comum.");
}

fn run_tui(open: Option<PathBuf>) -> Result<(), String> {
    let result = match &open {
        Some(p) => Some(xml::read_file(p)?),
        None => None,
    };
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        return Err(
            "O nscope é uma interface de terminal: execute-o diretamente em um terminal.".into(),
        );
    }
    let mut app = App::new(Env::detect());
    if let Some(r) = result {
        app.open_result(r);
    }
    let mut term = ratatui::init(); // instala o hook de pânico que restaura o terminal
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(std::io::stdout(), DisableMouseCapture);
        prev(info);
    }));
    let res = (|| -> std::io::Result<()> {
        while !app.quit {
            term.draw(|f| ui::draw(f, &mut app))?;
            if event::poll(Duration::from_millis(100))? {
                loop {
                    match event::read()? {
                        Event::Key(k) => app.on_key(k),
                        Event::Mouse(m) => app.on_mouse(m),
                        _ => {} // redimensionar: o próximo desenho já reorganiza o layout
                    }
                    if !event::poll(Duration::ZERO)? {
                        break;
                    }
                }
            }
            app.tick();
            if let Some(text) = app.copy_request.take() {
                let mut out = std::io::stdout();
                out.write_all(util::osc52(&text).as_bytes())?;
                out.flush()?;
            }
        }
        Ok(())
    })();
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    drop(app); // encerra o nmap filho (se houver) e remove os temporários
    res.map_err(|e| format!("Erro de terminal: {e}"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match parse_args(&args) {
        Cli::Exit(msg, c) => {
            if c == 0 {
                println!("{msg}")
            } else {
                eprintln!("{msg}")
            }
            c
        }
        Cli::Print { profile, target } => match print_command(profile, target) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                2
            }
        },
        Cli::Tui(open) => {
            #[cfg(unix)]
            elevate(&args);
            match run_tui(open) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
    };
    std::process::exit(code);
}
