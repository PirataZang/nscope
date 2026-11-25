//! Desenho da interface (ratatui). Só lê o `App`; o único efeito é registrar regiões clicáveis.

pub mod command;
pub mod editor;
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

/// Quebra pedaços coloridos em linhas de até `width` colunas, sem perder a cor de cada palavra.
pub fn wrap_spans(spans: &[Span<'static>], width: usize) -> Vec<Vec<Span<'static>>> {
    let width = width.max(1);
    let mut out: Vec<Vec<Span<'static>>> = vec![vec![]];
    let mut w = 0usize;
    for sp in spans {
        for (n, word) in sp.content.split(' ').enumerate() {
            let ww = word.width();
            let space = usize::from(n > 0 || w > 0);
            if w > 0 && w + space + ww > width {
                out.push(vec![]);
                w = 0;
            }
            let line = out.last_mut().expect("sempre há uma linha");
            let text = if w > 0 && n > 0 {
                format!(" {word}")
            } else {
                word.to_string()
            };
            w += text.width();
            if !text.is_empty() {
                line.push(Span::styled(text, sp.style));
            }
        }
    }
    out
}

/// Tabela de duas colunas: chave à esquerda (largura fixa) e texto quebrado, alinhado à direita.
/// Quando a coluna de texto ficaria estreita demais, a chave vai em uma linha e o texto embaixo, recuado.
pub fn kv_lines(
    rows: &[(Vec<Span<'static>>, Vec<Span<'static>>)],
    width: usize,
    key_max: usize,
) -> Vec<Line<'static>> {
    let span_w = |v: &Vec<Span>| v.iter().map(|s| s.content.width()).sum::<usize>();
    let key_w = rows
        .iter()
        .map(|(k, _)| span_w(k))
        .max()
        .unwrap_or(0)
        .min(key_max);
    let col = key_w + 2;
    let stacked = width < col + 24;
    let mut out = Vec::new();
    for (k, v) in rows {
        let kw = span_w(k);
        if stacked || kw > key_w {
            out.push(Line::from(k.clone()));
            for l in wrap_spans(v, width.saturating_sub(2)) {
                let mut l2 = vec![Span::raw("  ")];
                l2.extend(l);
                out.push(Line::from(l2));
            }
            continue;
        }
        for (n, l) in wrap_spans(v, width - col).into_iter().enumerate() {
            let mut line = if n == 0 {
                let mut x = k.clone();
                x.push(Span::raw(" ".repeat(col - kw)));
                x
            } else {
                vec![Span::raw(" ".repeat(col))]
            };
            line.extend(l);
            out.push(Line::from(line));
        }
    }
    out
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
    let full: Vec<String> = i18n::TABS
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
    // em terminais estreitos: nomes curtos e um espaço só entre as abas
    let items = if full.iter().map(|s| s.width()).sum::<usize>() <= tabs.width as usize {
        full
    } else {
        i18n::TABS_SHORT
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let e = if i == 3 && errs > 0 { "✘" } else { "" };
                format!(" {} {n}{e}", i + 1)
            })
            .collect()
    };
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
        Tab::Editar => editor::draw(f, app, body, &tokens, &findings),
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
    } else if app.cmd_edit.is_some() {
        i18n::FOOTER_CMD_EDIT.to_vec()
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
                a.open_result(xml::parse(include_str!("../../fixtures/basico.xml")).unwrap());
                a.history[0].when = "2026-11-25_12-30-05".into();
                a.save_dir = "/home/voce/projetos".into();
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
    fn editar_mostra_o_comando_em_edicao_e_os_problemas() {
        use ratatui::crossterm::event::KeyCode;
        let mut a = test_app();
        press(&mut a, KeyCode::Char('5'));
        press(&mut a, KeyCode::Enter);
        for c in " -sU --flag-nova=2".chars() {
            press(&mut a, KeyCode::Char(c));
        }
        let out = render(&mut a, 80, 24);
        insta::assert_snapshot!("editar_editando_80x24", out);
        press(&mut a, KeyCode::Char('|'));
        let out = render(&mut a, 80, 24);
        assert!(out.contains("não é aceito"), "{out}");
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
    fn busca_aparece_como_janela_e_alvo_externo_nao_pede_confirmacao() {
        let mut a = test_app();
        press(&mut a, ratatui::crossterm::event::KeyCode::Char('/'));
        press(&mut a, ratatui::crossterm::event::KeyCode::Char('u'));
        press(&mut a, ratatui::crossterm::event::KeyCode::Char('d'));
        let out = render(&mut a, 80, 24);
        insta::assert_snapshot!("busca_80x24", out);
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
