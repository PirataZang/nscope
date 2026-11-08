//! Desenho da interface (ratatui). Só lê o `App`; o único efeito é registrar regiões clicáveis.

pub mod command;
pub mod help;
pub mod options;
pub mod profiles;
pub mod results;
pub mod run;
pub mod target;
pub mod theme;
pub mod widgets;

use crate::app::{App, Hit, Lvl, Tab};
use crate::i18n;
use crate::nmap::analyze::Level;
use crate::nmap::catalog::Section;
use crate::nmap::command::{Class, Token};
use crate::util::truncate;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use theme::Theme;
use unicode_width::UnicodeWidthStr;

pub const MIN_W: u16 = 80;
pub const MIN_H: u16 = 24;

pub fn block<'a>(t: &Theme, title: &str) -> Block<'a> {
    Block::bordered()
        .border_style(t.border())
        .title(Span::styled(format!(" {title} "), t.accent()))
}

/// Retângulo interno de um bloco com borda.
pub fn inner(r: Rect) -> Rect {
    Rect {
        x: r.x + 1,
        y: r.y + 1,
        width: r.width.saturating_sub(2),
        height: r.height.saturating_sub(2),
    }
}

pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 3,
        width: w,
        height: h,
    }
}

/// Título de seção dentro dos painéis de detalhe.
pub fn heading(t: &Theme, text: &str, warn: bool) -> Line<'static> {
    Line::from(Span::styled(
        text.to_uppercase(),
        if warn {
            t.warn().add_modifier(Modifier::BOLD)
        } else {
            t.dim().add_modifier(Modifier::BOLD)
        },
    ))
}

pub fn badge(t: &Theme, text: &str, style: Style) -> Span<'static> {
    let _ = t;
    Span::styled(format!("[{text}]"), style)
}

pub fn token_spans(t: &Theme, tok: &Token) -> Vec<Span<'static>> {
    tok.parts
        .iter()
        .map(|(s, c)| {
            let st = match c {
                Class::Program => t.program(),
                Class::Flag => t.flag(),
                Class::Value => t.normal(),
                Class::Target => t.value(),
                Class::Plain => t.dim(),
            };
            Span::styled(s.clone(), st)
        })
        .collect()
}

/// Comando colorido, quebrado em linhas de `width` colunas (quebra só entre tokens).
pub fn command_lines(t: &Theme, tokens: &[Token], width: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Vec<Span<'static>>> = vec![vec![
        Span::styled("$ ", t.ok()),
        Span::styled("nmap", t.program()),
    ]];
    let mut w = 6usize;
    for tok in tokens {
        let tw: usize = tok.display().width();
        if w + 1 + tw > width && w > 2 {
            lines.push(vec![Span::raw("  ")]);
            w = 2;
        }
        if let Some(last) = lines.last_mut() {
            last.push(Span::raw(" "));
            last.extend(token_spans(t, tok));
        }
        w += 1 + tw;
    }
    lines.into_iter().map(Line::from).collect()
}

/// Abas em uma linha, com janela horizontal para manter a selecionada visível. Registra cliques.
pub fn tab_strip(
    f: &mut Frame,
    app: &mut App,
    area: Rect,
    items: &[String],
    selected: usize,
    mk: fn(usize) -> Hit,
    (on, off): (Style, Style),
) {
    let widths: Vec<usize> = items.iter().map(|s| s.width()).collect();
    let total = area.width as usize;
    let mut start = 0;
    while start < selected
        && widths[start..=selected].iter().sum::<usize>() > total.saturating_sub(2)
    {
        start += 1;
    }
    let mut spans = Vec::new();
    let mut x = area.x;
    if start > 0 {
        spans.push(Span::styled("‹", off));
        x += 1;
    }
    for i in start..items.len() {
        let w = widths[i] as u16;
        if x + w > area.x + area.width {
            spans.push(Span::styled("›", off));
            break;
        }
        spans.push(Span::styled(
            items[i].clone(),
            if i == selected { on } else { off },
        ));
        app.hits.push((
            Rect {
                x,
                y: area.y,
                width: w,
                height: 1,
            },
            mk(i),
        ));
        x += w;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    app.hits.clear();
    let t = app.theme;
    if area.width < MIN_W || area.height < MIN_H {
        let msg = Text::from(vec![
            Line::from(Span::styled(i18n::MIN_SIZE, t.err())),
            Line::from(i18n::MIN_SIZE_HELP),
            Line::from(format!(
                "{}: {}x{}",
                i18n::MIN_SIZE_NOW,
                area.width,
                area.height
            )),
        ]);
        f.render_widget(
            Paragraph::new(msg)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            centered(area, area.width, 4),
        );
        return;
    }
    let tokens = app.tokens();
    let findings = app.findings();
    let has_err = findings.iter().any(|x| x.level == Level::Error);
    let cmd_w = area.width as usize - 1;
    let mut cmd = command_lines(&t, &tokens, cmd_w);
    cmd.truncate(4);
    let cmd_h = cmd.len() as u16 + 1;
    let subs_h = u16::from(app.tab == Tab::Configurar);
    let [title, tabs, subs, body, cmdbar, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(subs_h),
        Constraint::Min(5),
        Constraint::Length(cmd_h),
        Constraint::Length(1),
    ])
    .areas(area);

    // título
    let (ptxt, pst) = if app.env.privileged {
        (i18n::PRIV_ADMIN, t.ok())
    } else {
        (i18n::PRIV_USER, t.warn())
    };
    let nmap = match &app.env.nmap {
        Ok(v) => Span::styled(
            v.trim_start_matches("Nmap version ")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string(),
            t.dim(),
        ),
        Err(_) => Span::styled(i18n::NMAP_MISSING_SHORT, t.err()),
    };
    let nmap_label = match &app.env.nmap {
        Ok(_) => Span::styled("nmap ", t.dim()),
        Err(_) => Span::raw(""),
    };
    let left = Line::from(vec![
        Span::styled(format!(" {} ", i18n::TITLE), t.accent()),
        Span::styled("· TUI do nmap · ", t.dim()),
        nmap_label,
        nmap,
    ]);
    f.render_widget(Paragraph::new(left), title);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Privilégios: ", t.dim()),
            Span::styled(ptxt, pst),
            Span::raw(" "),
        ]))
        .alignment(Alignment::Right),
        title,
    );

    // abas
    let errs = findings.iter().filter(|x| x.level == Level::Error).count();
    let items: Vec<String> = i18n::TABS
        .iter()
        .enumerate()
        .map(|(i, n)| {
            if i == 3 && errs > 0 {
                format!(" {} {n}✘{errs} ", i + 1)
            } else {
                format!(" {} {n} ", i + 1)
            }
        })
        .collect();
    tab_strip(
        f,
        app,
        tabs,
        &items,
        app.tab.index(),
        Hit::Tab,
        (t.tab_on(), t.dim()),
    );
    if subs_h == 1 {
        let items: Vec<String> = Section::CONFIG
            .iter()
            .map(|s| {
                let c = app.values.active_count(*s);
                if c > 0 {
                    format!(" {}•{c} ", s.short())
                } else {
                    format!(" {} ", s.short())
                }
            })
            .collect();
        tab_strip(
            f,
            app,
            subs,
            &items,
            app.sub,
            Hit::Sub,
            (t.accent().add_modifier(Modifier::UNDERLINED), t.dim()),
        );
    }

    match app.tab {
        Tab::Alvo => target::draw(f, app, body),
        Tab::Perfis => profiles::draw(f, app, body),
        Tab::Configurar => options::draw(f, app, body),
        Tab::Comando => command::draw(f, app, body, &tokens, &findings),
        Tab::Execucao => run::draw(f, app, body),
        Tab::Resultados => results::draw(f, app, body),
        Tab::Ajuda => help::draw(f, app, body),
    }

    // barra de comando fixa (sempre visível)
    let bs = if has_err { t.err() } else { t.border() };
    let blk = Block::new()
        .borders(Borders::TOP)
        .border_style(bs)
        .title(Span::styled(
            format!(" {} ", i18n::PANEL_COMMAND),
            t.accent(),
        ));
    f.render_widget(blk, cmdbar);
    let btn_run = " ▶ Executar (r) ";
    let btn_copy = " Copiar (y) ";
    let (rw, cw) = (btn_run.width() as u16, btn_copy.width() as u16);
    if cmdbar.width > rw + cw + 20 {
        let rr = Rect {
            x: cmdbar.x + cmdbar.width - rw - 1,
            y: cmdbar.y,
            width: rw,
            height: 1,
        };
        let cr = Rect {
            x: rr.x - cw - 1,
            y: cmdbar.y,
            width: cw,
            height: 1,
        };
        f.render_widget(Paragraph::new(Span::styled(btn_run, t.tab_on())), rr);
        f.render_widget(Paragraph::new(Span::styled(btn_copy, t.selected())), cr);
        app.hits.push((rr, Hit::Run));
        app.hits.push((cr, Hit::Copy));
    }
    f.render_widget(
        Paragraph::new(Text::from(cmd)),
        Rect {
            x: cmdbar.x,
            y: cmdbar.y + 1,
            width: cmdbar.width,
            height: cmdbar.height - 1,
        },
    );

    draw_footer(f, app, foot);
    if app.search.is_some() {
        draw_search(f, app, area);
    }
    if app.confirm.is_some() {
        draw_confirm(f, app, area);
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let t = app.theme;
    if let Some(fl) = app.flash_active() {
        let st = match fl.lvl {
            Lvl::Ok => t.ok(),
            Lvl::Warn => t.warn(),
            Lvl::Err => t.err(),
        };
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" {}", truncate(&fl.msg, area.width as usize - 2)),
                st,
            )),
            area,
        );
        return;
    }
    let hints: Vec<(&str, &str)> = if app.edit.is_some() {
        i18n::FOOTER_EDIT.to_vec()
    } else {
        i18n::footer(app.tab.index())
    };
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1usize;
    for (k, d) in hints {
        let w = k.width() + d.width() + 3;
        if used + w > area.width as usize {
            break;
        }
        spans.push(Span::styled(k, t.accent()));
        spans.push(Span::styled(format!(" {d}  "), t.dim()));
        used += w;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_search(f: &mut Frame, app: &App, area: Rect) {
    let t = app.theme;
    let Some(s) = &app.search else { return };
    let hits = app.search_hits();
    let h = (hits.len().min(12) as u16 + 5).max(6);
    let r = centered(area, 74.min(area.width), h);
    f.render_widget(Clear, r);
    f.render_widget(block(&t, "Buscar"), r);
    let i = inner(r);
    let (b, a, af) = s.input.view(i.width as usize - 2);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("/ ", t.accent()),
            Span::raw(b),
            Span::styled(a, t.selected()),
            Span::raw(af),
        ])),
        Rect { height: 1, ..i },
    );
    f.render_widget(
        Paragraph::new(Span::styled(i18n::SEARCH_PROMPT, t.dim())),
        Rect {
            y: i.y + 1,
            height: 1,
            ..i
        },
    );
    let list = Rect {
        y: i.y + 2,
        height: i.height.saturating_sub(3),
        ..i
    };
    if hits.is_empty() {
        f.render_widget(Paragraph::new(i18n::SEARCH_NONE), list);
    } else {
        let off = widgets::list::scroll_offset(0, s.sel, list.height as usize, hits.len());
        let lines: Vec<Line> = hits
            .iter()
            .enumerate()
            .skip(off)
            .take(list.height as usize)
            .map(|(n, o)| {
                let flag = if o.flag.is_empty() { "·" } else { o.flag };
                let txt = format!(
                    " {:<18} {:<34} {}",
                    truncate(flag, 18),
                    truncate(o.label, 34),
                    o.section.short()
                );
                Line::from(Span::styled(
                    truncate(&txt, list.width as usize),
                    if n == s.sel { t.selected() } else { t.normal() },
                ))
            })
            .collect();
        f.render_widget(Paragraph::new(lines), list);
    }
    f.render_widget(
        Paragraph::new(Span::styled("↑↓ escolher · Enter ir · Esc fechar", t.dim())),
        Rect {
            y: i.y + i.height - 1,
            height: 1,
            ..i
        },
    );
}

fn draw_confirm(f: &mut Frame, app: &App, area: Rect) {
    let t = app.theme;
    let Some(c) = &app.confirm else { return };
    let shown: Vec<String> = c.targets.iter().take(4).cloned().collect();
    let more = c.targets.len().saturating_sub(4);
    let h = 10 + shown.len() as u16 + u16::from(more > 0);
    let r = centered(area, 70.min(area.width), h);
    f.render_widget(Clear, r);
    f.render_widget(
        Block::bordered()
            .border_style(t.warn())
            .title(Span::styled(format!(" {} ", i18n::CONFIRM_TITLE), t.warn())),
        r,
    );
    let i = inner(r);
    let mut lines = vec![
        Line::from(Span::styled(i18n::CONFIRM_ASK, t.bold())),
        Line::raw(""),
    ];
    for s in shown {
        lines.push(Line::from(vec![
            Span::raw("  • "),
            Span::styled(s, t.value()),
        ]));
    }
    if more > 0 {
        lines.push(Line::from(Span::styled(
            format!("  … e mais {more}"),
            t.dim(),
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(i18n::CONFIRM_NOTE, t.dim())));
    lines.push(Line::raw(""));
    let (no, yes) = (
        format!("  {}  ", i18n::CONFIRM_NO),
        format!("  {}  ", i18n::CONFIRM_YES),
    );
    lines.push(Line::from(vec![
        Span::styled(no, if c.yes { t.normal() } else { t.selected() }),
        Span::raw("   "),
        Span::styled(
            yes,
            if c.yes {
                t.warn().add_modifier(Modifier::REVERSED)
            } else {
                t.normal()
            },
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "←→ escolher · Enter confirmar · Esc cancela",
        t.dim(),
    )));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), i);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::app::{App, Env};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    pub fn test_app() -> App {
        let mut a = App::new(Env {
            privileged: false,
            nmap: Ok("Nmap version 7.95".into()),
            program: "nmap".into(),
        });
        a.theme = Theme { color: false };
        a
    }

    /// Renderiza em texto puro (sem cores) para snapshots.
    pub fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    use crate::app::{LogKind, LogLine, RunState, Tab};
    use crate::nmap::runner::Progress;
    use crate::nmap::xml;

    fn press(a: &mut App, c: ratatui::crossterm::event::KeyCode) {
        a.on_key(ratatui::crossterm::event::KeyEvent::new(
            c,
            ratatui::crossterm::event::KeyModifiers::NONE,
        ));
    }

    /// Estado determinístico para cada aba.
    fn prepared(tab: Tab) -> App {
        let mut a = test_app();
        a.values.set("sV", "1");
        a.values.set("oA", "relatorio");
        a.set_tab(tab);
        match tab {
            Tab::Configurar => {
                a.sub = 2;
            }
            Tab::Execucao => {
                a.run_state = RunState::Running;
                a.run_command = "nmap -sV scanme.nmap.org".into();
                a.run_progress = Some(Progress {
                    percent: 42.0,
                    remaining: Some("0:00:12".into()),
                });
                for (t, k) in [
                    ("Starting Nmap 7.95 ( https://nmap.org )", LogKind::Head),
                    ("Discovered open port 22/tcp on 192.0.2.10", LogKind::Open),
                    ("Warning: osscan results may be unreliable", LogKind::Warn),
                    (
                        "SYN Stealth Scan Timing: About 42.00% done; ETC: 14:03 (0:00:12 remaining)",
                        LogKind::Normal,
                    ),
                ] {
                    a.log.push_back(LogLine {
                        text: t.into(),
                        kind: k,
                    });
                }
            }
            Tab::Resultados => {
                a.result = Some(xml::parse(include_str!("../../fixtures/basico.xml")).unwrap());
                press(&mut a, ratatui::crossterm::event::KeyCode::Right);
            }
            _ => {}
        }
        a
    }

    #[test]
    fn snapshots_de_todas_as_abas() {
        for tab in Tab::ALL {
            for (w, h) in [(80, 24), (120, 40)] {
                let mut a = prepared(tab);
                let out = render(&mut a, w, h);
                insta::assert_snapshot!(format!("{tab:?}_{w}x{h}").to_lowercase(), out);
            }
        }
    }

    #[test]
    fn terminal_pequeno_mostra_mensagem() {
        let mut a = test_app();
        let out = render(&mut a, 60, 20);
        assert!(
            out.contains("Janela pequena demais")
                && out.contains("80 colunas por 24 linhas")
                && out.contains("60x20"),
            "{out}"
        );
        let out = render(&mut a, 80, 23);
        assert!(out.contains("Janela pequena demais"));
        let out = render(&mut a, 80, 24);
        assert!(!out.contains("Janela pequena demais"));
    }

    #[test]
    fn busca_e_confirmacao_aparecem_como_janelas() {
        let mut a = test_app();
        press(&mut a, ratatui::crossterm::event::KeyCode::Char('/'));
        press(&mut a, ratatui::crossterm::event::KeyCode::Char('u'));
        press(&mut a, ratatui::crossterm::event::KeyCode::Char('d'));
        let out = render(&mut a, 80, 24);
        insta::assert_snapshot!("busca_80x24", out);
        let mut b = test_app();
        b.values.set("targets", "8.8.8.8 1.1.1.1");
        press(&mut b, ratatui::crossterm::event::KeyCode::Char('r'));
        let out = render(&mut b, 80, 24);
        assert!(
            out.contains("Você tem autorização para escanear estes alvos?")
                && out.contains("8.8.8.8")
        );
        insta::assert_snapshot!("confirmacao_80x24", out);
    }

    #[test]
    fn nenhuma_celula_tem_caractere_de_controle_mesmo_com_dados_hostis() {
        // dados hostis já entram sanitizados (xml/runner); aqui garantimos que o desenho não os reintroduz
        let mut a = prepared(Tab::Resultados);
        let out = render(&mut a, 120, 40);
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn mouse_clica_em_abas_e_linhas() {
        use ratatui::crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        let click = |a: &mut App, x: u16, y: u16| {
            a.on_mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: x,
                row: y,
                modifiers: KeyModifiers::NONE,
            });
        };
        let mut a = test_app();
        render(&mut a, 80, 24);
        let (r, _) = *a.hits.iter().find(|(_, h)| *h == Hit::Tab(2)).unwrap();
        click(&mut a, r.x + 1, r.y);
        assert_eq!(a.tab, Tab::Configurar);
        render(&mut a, 80, 24);
        let (r, _) = *a.hits.iter().find(|(_, h)| *h == Hit::Sub(5)).unwrap();
        click(&mut a, r.x, r.y);
        assert_eq!(a.sub, 5);
        render(&mut a, 80, 24);
        let (r, _) = *a.hits.iter().find(|(_, h)| *h == Hit::Row(1)).unwrap(); // --min-hostgroup
        click(&mut a, r.x + 2, r.y);
        assert!(
            a.edit.is_some(),
            "clicar em uma opção de texto abre a edição"
        );
    }
}
