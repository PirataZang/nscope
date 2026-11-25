//! Tela Resultados: hosts · portas · detalhes, filtro "só abertas".

use super::{block, heading, inner};
use crate::app::{App, Hit, Pane};
use crate::nmap::knowledge::{self, Risk};
use crate::nmap::xml::{Host, Port};
use crate::util::truncate;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

fn state_style(app: &App, st: &str) -> Style {
    let t = &app.theme;
    match st {
        "open" => t.ok(),
        "closed" => t.err(),
        "filtered" | "unfiltered" | "open|filtered" | "closed|filtered" => t.warn(),
        _ => t.normal(),
    }
}

/// Histórico de execuções da sessão: uma linha por execução, a escolhida em destaque.
fn draw_runs(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    let focus = app.pane == Pane::Runs;
    f.render_widget(
        block(
            &t,
            &format!(
                "Execuções ({}){}",
                app.history.len(),
                if focus { " ◂" } else { "" }
            ),
        ),
        area,
    );
    let i = inner(area);
    let w = i.width as usize;
    let off =
        super::widgets::list::scroll_offset(0, app.hist_i, i.height as usize, app.history.len());
    let mut lines = Vec::new();
    for (n, e) in app
        .history
        .iter()
        .enumerate()
        .skip(off)
        .take(i.height as usize)
    {
        app.hits.push((
            Rect {
                x: i.x,
                y: i.y + (n - off) as u16,
                width: i.width,
                height: 1,
            },
            Hit::Exec(n),
        ));
        let (icon, st) = if e.status == "concluído" {
            ("✔", t.ok())
        } else if e.status == "cancelado" {
            ("■", t.warn())
        } else if e.status.starts_with("falhou") {
            ("✘", t.err())
        } else if e.status.starts_with("aberto") {
            ("◇", t.accent())
        } else {
            ("⚠", t.warn())
        };
        let clock = e.clock();
        let cmd = e.command.strip_prefix("nmap ").unwrap_or(&e.command);
        let txt = truncate(
            &format!("{:>2} {} {icon} {cmd}", n + 1, clock.get(..5).unwrap_or("")),
            w,
        );
        let cur = n == app.hist_i;
        lines.push(if cur && focus {
            let pad = w.saturating_sub(txt.width());
            Line::styled(format!("{txt}{}", " ".repeat(pad)), t.selected())
        } else if cur {
            Line::styled(txt, t.accent())
        } else {
            Line::from(vec![Span::styled(
                txt,
                if icon == "✔" { t.normal() } else { st },
            )])
        });
    }
    f.render_widget(Paragraph::new(lines), i);
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    if app.history.is_empty() && app.result.is_none() {
        f.render_widget(block(&t, "Resultados"), area);
        f.render_widget(
            Paragraph::new(crate::i18n::NO_RESULTS).wrap(Wrap { trim: false }),
            inner(area),
        );
        return;
    }
    let warn = app.result.as_ref().is_some_and(|r| !r.warnings.is_empty());
    let [head, rest] = Layout::vertical([
        Constraint::Length(if warn { 3 } else { 2 }),
        Constraint::Min(5),
    ])
    .areas(area);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(32), Constraint::Min(30)]).areas(rest);
    let hosts = if app.history.is_empty() {
        left
    } else {
        let h = (app.history.len() as u16 + 2).min((left.height / 3).max(4));
        let [runs, hosts] =
            Layout::vertical([Constraint::Length(h), Constraint::Min(3)]).areas(left);
        draw_runs(f, app, runs);
        hosts
    };
    let n = app.history.len();
    let save_hint = format!(
        "· s salva o histórico ({n} execuç{}) em {}",
        if n == 1 { "ão" } else { "ões" },
        app.save_dir.display()
    );
    let Some(res) = app.result.clone() else {
        // execução sem resultado (cancelada, falhou, só informação)
        let e = &app.history[app.hist_i.min(n - 1)];
        let msg = vec![
            Line::from(vec![
                Span::styled(format!(" Execução {} · ", app.hist_i + 1), t.normal()),
                Span::styled(truncate(&e.command, head.width as usize / 2), t.dim()),
            ]),
            Line::styled(
                truncate(&format!(" {save_hint}"), head.width as usize),
                t.dim(),
            ),
        ];
        f.render_widget(Paragraph::new(msg), head);
        f.render_widget(block(&t, "Hosts"), hosts);
        f.render_widget(block(&t, "Resultado"), right);
        f.render_widget(
            Paragraph::new(vec![
                Line::styled(format!("Esta execução terminou como: {}.", e.status), t.warn()),
                Line::raw(""),
                Line::raw("Ela não gerou hosts nem portas. A saída do nmap fica guardada no histórico e vai junto quando você salvar (s)."),
                Line::raw(""),
                Line::styled("← escolha outra execução na lista", t.dim()),
            ])
            .wrap(Wrap { trim: false }),
            inner(right),
        );
        return;
    };
    let dur = res
        .duration_secs
        .map_or(String::new(), |d| format!(" · {d:.1} s"));
    let mut hl = vec![
        Line::from(vec![
            Span::styled(
                format!(
                    " {} hosts ({} ligados){dur} · ",
                    res.hosts_total.max(res.hosts.len() as u32),
                    res.hosts_up
                ),
                t.normal(),
            ),
            Span::styled(
                truncate(&res.command, head.width.saturating_sub(40) as usize),
                t.dim(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                if app.only_open {
                    " ✔ só abertas (o) "
                } else {
                    " ☐ só abertas (o) "
                },
                t.accent(),
            ),
            Span::styled(
                truncate(&save_hint, (head.width as usize).saturating_sub(20)),
                t.dim(),
            ),
        ]),
    ];
    if let Some(w) = res.warnings.first() {
        hl.push(Line::styled(
            format!(" ⚠ {}", truncate(w, head.width as usize - 5)),
            t.warn(),
        ));
    }
    f.render_widget(Paragraph::new(hl), head);

    let [ports, det] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(right);

    // hosts
    let hi = app.host_i.min(res.hosts.len().saturating_sub(1));
    f.render_widget(
        block(
            &t,
            &format!("Hosts{}", if app.pane == Pane::Hosts { " ◂" } else { "" }),
        ),
        hosts,
    );
    let i = inner(hosts);
    let off = super::widgets::list::scroll_offset(0, hi, i.height as usize, res.hosts.len());
    let lines: Vec<Line> = res
        .hosts
        .iter()
        .enumerate()
        .skip(off)
        .take(i.height as usize)
        .map(|(n, h)| {
            app.hits.push((
                Rect {
                    x: i.x,
                    y: i.y + (n - off) as u16,
                    width: i.width,
                    height: 1,
                },
                Hit::Host(n),
            ));
            let name = if h.hostname.is_empty() {
                h.address.clone()
            } else {
                format!("{} {}", h.address, h.hostname)
            };
            let right = format!("{} ab.", h.open_count());
            let dot = if h.is_up() { "● " } else { "○ " };
            let room = (i.width as usize).saturating_sub(right.width() + 3);
            let txt = format!("{dot}{:<room$} {right}", truncate(&name, room));
            Line::styled(
                txt,
                if n == hi {
                    t.selected()
                } else if h.is_up() {
                    t.normal()
                } else {
                    t.dim()
                },
            )
        })
        .collect();
    f.render_widget(Paragraph::new(lines), i);

    let Some(host) = res.hosts.get(hi) else {
        return;
    };
    let plist: Vec<&Port> = host
        .ports
        .iter()
        .filter(|p| !app.only_open || p.is_open())
        .collect();
    let pi = app.port_i.min(plist.len().saturating_sub(1));

    // portas
    f.render_widget(
        block(
            &t,
            &format!("Portas{}", if app.pane == Pane::Ports { " ◂" } else { "" }),
        ),
        ports,
    );
    let i = inner(ports);
    let w = i.width as usize;
    let c1 = 9usize;
    let c2 = 15usize.min(w / 3);
    let c3 = 14usize.min(w / 3);
    let mut lines = vec![Line::styled(
        format!("{:<c1$}{:<c2$}{:<c3$}VERSÃO", "PORTA", "ESTADO", "SERVIÇO"),
        t.dim(),
    )];
    let hidden: Vec<String> = host
        .hidden
        .iter()
        .map(|x| {
            format!(
                "Não exibidas: {} portas {} ({})",
                x.count, x.state, x.reason
            )
        })
        .collect();
    let room = (i.height as usize).saturating_sub(1 + hidden.len().min(1));
    let off = super::widgets::list::scroll_offset(0, pi, room, plist.len());
    for (n, p) in plist.iter().enumerate().skip(off).take(room) {
        app.hits.push((
            Rect {
                x: i.x,
                y: i.y + 1 + (n - off) as u16,
                width: i.width,
                height: 1,
            },
            Hit::Port(n),
        ));
        let left = format!("{:<c1$}", format!("{}/{}", p.number, p.protocol));
        let st = format!("{:<c2$}", truncate(&p.state, c2 - 1));
        let sv = format!("{:<c3$}", truncate(&p.service, c3 - 1));
        let ver = truncate(&p.version_text(), w.saturating_sub(c1 + c2 + c3));
        let sel = n == pi && app.pane == Pane::Ports;
        if sel {
            lines.push(Line::styled(
                truncate(&format!("{left}{st}{sv}{ver}"), w),
                t.selected(),
            ));
        } else {
            lines.push(Line::from(vec![
                Span::raw(left),
                Span::styled(st, state_style(app, &p.state)),
                Span::raw(sv),
                Span::styled(ver, t.dim()),
            ]));
        }
    }
    if let Some(h) = hidden.first() {
        lines.push(Line::styled(truncate(h, w), t.dim()));
    }
    f.render_widget(Paragraph::new(lines), i);

    // detalhes
    f.render_widget(block(&t, "Detalhes"), det);
    let lines = if app.pane == Pane::Ports && !plist.is_empty() {
        port_detail(app, plist[pi])
    } else {
        host_detail(app, host, res.hosts_total == 0)
    };
    app.detail_scroll = app.detail_scroll.min(lines.len().saturating_sub(1));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll as u16, 0)),
        inner(det),
    );
}

fn host_detail(app: &App, h: &Host, _empty: bool) -> Vec<Line<'static>> {
    let t = &app.theme;
    let mut v = vec![Line::styled(
        if h.hostname.is_empty() {
            h.address.clone()
        } else {
            format!("{} ({})", h.hostname, h.address)
        },
        t.bold(),
    )];
    v.push(Line::from(vec![
        Span::styled(
            if h.is_up() {
                "● ligado"
            } else {
                "○ desligado"
            },
            if h.is_up() { t.ok() } else { t.dim() },
        ),
        Span::raw(if h.mac.is_empty() {
            String::new()
        } else {
            format!(" · MAC {}", h.mac)
        }),
    ]));
    if let Some(os) = &h.os {
        v.push(Line::raw(""));
        v.push(heading(t, "Sistema operacional (estimado)", false));
        v.push(Line::raw(format!(
            "{} ({}% de certeza)",
            os.name, os.accuracy
        )));
    }
    if !h.hops.is_empty() {
        v.push(Line::raw(""));
        v.push(heading(t, "Rota", false));
        for hop in &h.hops {
            let name = if hop.host.is_empty() {
                hop.address.clone()
            } else {
                format!("{} ({})", hop.host, hop.address)
            };
            v.push(Line::raw(format!(
                "{:>2}. {name} · {} ms",
                hop.ttl, hop.rtt
            )));
        }
    }
    if !h.scripts.is_empty() {
        v.push(Line::raw(""));
        v.push(heading(t, "Scripts do host", false));
        for s in &h.scripts {
            v.push(Line::styled(s.id.clone(), t.flag()));
            v.extend(
                s.output
                    .lines()
                    .map(|l| Line::styled(format!("  {l}"), t.dim())),
            );
        }
    }
    v.push(Line::raw(""));
    v.push(Line::styled(
        "Dica: → ou clique em uma porta para ver o que ela significa e os riscos.",
        t.dim(),
    ));
    v
}

fn port_detail(app: &App, p: &Port) -> Vec<Line<'static>> {
    let t = &app.theme;
    let info = knowledge::port_info(p.number);
    let mut v = vec![Line::styled(
        format!(
            "{}/{} {}{}",
            p.number,
            p.protocol,
            p.service,
            info.map_or(String::new(), |i| format!(" · {}", i.name))
        ),
        t.bold(),
    )];
    v.push(Line::from(vec![
        Span::styled(p.state.clone(), state_style(app, &p.state)),
        Span::raw(" · motivo: "),
        Span::styled(p.reason.clone(), t.flag()),
    ]));
    v.push(Line::raw(""));
    v.push(heading(t, "Significa", false));
    v.push(Line::raw(knowledge::state_help(&p.state)));
    if let Some(i) = info {
        v.push(Line::raw(""));
        v.push(heading(t, i.risk.exposure_label(), i.risk != Risk::Info));
        v.push(Line::styled(
            i.text,
            if i.risk == Risk::High {
                t.warn()
            } else {
                t.normal()
            },
        ));
    }
    let ver = p.version_text();
    if !ver.is_empty() {
        v.push(Line::raw(""));
        v.push(heading(t, "Versão detectada", false));
        v.push(Line::raw(format!(
            "{ver}{}",
            if p.tunnel.is_empty() {
                String::new()
            } else {
                format!(" · túnel {}", p.tunnel)
            }
        )));
    }
    if !p.scripts.is_empty() {
        v.push(Line::raw(""));
        v.push(heading(t, "Saída dos scripts", false));
        for s in &p.scripts {
            v.push(Line::styled(s.id.clone(), t.flag()));
            v.extend(
                s.output
                    .lines()
                    .map(|l| Line::styled(format!("  {l}"), t.dim())),
            );
        }
    }
    v
}
