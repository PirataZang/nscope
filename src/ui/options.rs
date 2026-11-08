//! Telas de opções (Alvo e Configurar): lista à esquerda, painel "O que isso faz" à direita.

use super::{badge, block, heading, inner};
use crate::app::{App, Hit, Row};
use crate::i18n;
use crate::nmap::catalog::{self, Fmt, Kind, Opt, Root};
use crate::nmap::knowledge::Risk;
use crate::nmap::validate;
use crate::util::truncate;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

pub fn split(area: Rect) -> [Rect; 2] {
    let left = (area.width * 42 / 100).clamp(38, 50);
    Layout::horizontal([Constraint::Length(left), Constraint::Min(20)]).areas(area)
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let [l, r] = split(area);
    let title = app.section().map_or("", |s| s.title());
    draw_list(f, app, l, title);
    draw_detail(f, app, r);
}

fn value_text(app: &App, o: &Opt) -> (String, bool) {
    match o.kind {
        Kind::Bool => (String::new(), false),
        Kind::Choice => {
            let c = o.choice(app.values.get(o.id));
            (
                c.map_or(String::new(), |c| {
                    c.label
                        .split(" (")
                        .next()
                        .unwrap_or("")
                        .split(": ")
                        .next()
                        .unwrap_or("")
                        .to_string()
                }),
                true,
            )
        }
        _ => {
            let v = app.values.text(o.id);
            if v.is_empty() {
                (o.placeholder.to_string(), false)
            } else {
                (v.to_string(), true)
            }
        }
    }
}

pub fn draw_list(f: &mut Frame, app: &mut App, area: Rect, title: &str) {
    let t = app.theme;
    f.render_widget(block(&t, title), area);
    let i = inner(area);
    let rows = app.rows();
    let cur = app.cursor().min(rows.len().saturating_sub(1));
    let key = app.list_key();
    let off = super::widgets::list::scroll_offset(
        app.list_offset[key],
        cur,
        i.height as usize,
        rows.len(),
    );
    app.list_offset[key] = off;
    let w = i.width as usize;
    let mut lines: Vec<Line> = Vec::new();
    for (n, row) in rows.iter().enumerate().skip(off).take(i.height as usize) {
        let sel = n == cur;
        let y = i.y + (n - off) as u16;
        app.hits.push((
            Rect {
                x: i.x,
                y,
                width: i.width,
                height: 1,
            },
            Hit::Row(n),
        ));
        let line = match row {
            Row::Header(h) => Line::from(Span::styled(
                truncate(h, w),
                t.dim().add_modifier(Modifier::BOLD),
            )),
            Row::Opt(o) => {
                let on = app.values.is_set(o);
                let mark = if on { "[x] " } else { "[ ] " };
                if let Some(e) = app.edit.as_ref().filter(|e| e.id == o.id && sel) {
                    let prefix = format!("{mark}{}: ", truncate(o.label, w / 2));
                    let room = w.saturating_sub(prefix.width()).max(4);
                    let (b, a, af) = e.input.view(room);
                    Line::from(vec![
                        Span::styled(prefix, t.accent()),
                        Span::raw(b),
                        Span::styled(a, t.selected()),
                        Span::raw(af),
                    ])
                } else {
                    let (val, set) = value_text(app, o);
                    let flag = if !o.flag.is_empty() && o.kind != Kind::Choice && w >= 44 {
                        format!(" {}", o.flag)
                    } else {
                        String::new()
                    };
                    let right = truncate(&val, (w * 2 / 5).max(8));
                    let left_room = w.saturating_sub(right.width() + 1);
                    let label = truncate(&format!("{mark}{}", o.label), left_room.max(6));
                    let flag = if label.width() + flag.width() + right.width() < w {
                        flag
                    } else {
                        String::new()
                    };
                    let pad = w.saturating_sub(label.width() + flag.width() + right.width());
                    if sel {
                        Line::from(Span::styled(
                            format!("{label}{flag}{}{right}", " ".repeat(pad)),
                            t.selected(),
                        ))
                    } else {
                        Line::from(vec![
                            Span::styled(label, if on { t.ok() } else { t.normal() }),
                            Span::styled(flag, t.flag()),
                            Span::raw(" ".repeat(pad)),
                            Span::styled(right, if set { t.value() } else { t.dim() }),
                        ])
                    }
                }
            }
            Row::Nse(item, cat) => {
                let on = app.script_items().iter().any(|x| x == item.0);
                let tag = match item.2 {
                    Risk::High => "perigoso",
                    Risk::Attention => "atenção",
                    Risk::Info if *cat => "categoria",
                    Risk::Info => "",
                };
                let label = format!("{} {}", if on { "[x]" } else { "[ ]" }, item.0);
                let pad = w.saturating_sub(label.width() + tag.width());
                if sel {
                    Line::from(Span::styled(
                        format!("{label}{}{tag}", " ".repeat(pad)),
                        t.selected(),
                    ))
                } else {
                    let st = match item.2 {
                        Risk::High => t.err(),
                        Risk::Attention => t.warn(),
                        Risk::Info => {
                            if on {
                                t.ok()
                            } else {
                                t.normal()
                            }
                        }
                    };
                    Line::from(vec![
                        Span::styled(label, st),
                        Span::raw(" ".repeat(pad)),
                        Span::styled(tag, t.dim()),
                    ])
                }
            }
        };
        lines.push(line);
    }
    f.render_widget(Paragraph::new(lines), i);
}

pub fn draw_detail(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    f.render_widget(block(&t, i18n::PANEL_WHAT), area);
    let lines = match app.selected_row() {
        Some(Row::Opt(o)) => opt_detail(app, o),
        Some(Row::Nse(item, cat)) => nse_detail(app, item, cat),
        _ => vec![Line::raw("Nenhuma opção visível.")],
    };
    let max = lines.len().saturating_sub(1);
    app.detail_scroll = app.detail_scroll.min(max);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll as u16, 0)),
        inner(area),
    );
}

fn risk_badge(app: &App, r: Risk) -> Option<Span<'static>> {
    let t = &app.theme;
    match r {
        Risk::High => Some(badge(t, "PERIGOSO", t.err())),
        Risk::Attention => Some(badge(t, "ATENÇÃO", t.warn())),
        Risk::Info => None,
    }
}

fn nse_detail(
    app: &App,
    item: &(&'static str, &'static str, Risk),
    cat: bool,
) -> Vec<Line<'static>> {
    let t = &app.theme;
    let mut title = vec![Span::styled(item.0.to_string(), t.bold()), Span::raw("  ")];
    title.extend(risk_badge(app, item.2));
    if cat {
        title.push(badge(t, "CATEGORIA", t.dim()));
    }
    let on = app.script_items().iter().any(|x| x == item.0);
    let mut v = vec![
        Line::from(title),
        Line::raw(""),
        heading(t, i18n::K_WHAT, false),
        Line::raw(item.1.to_string()),
    ];
    if item.2 == Risk::High {
        v.push(Line::raw(""));
        v.push(heading(t, i18n::K_CAUTION, true));
        v.push(Line::raw(
            "Pode derrubar serviços, bloquear contas e gerar alertas. Só com autorização expressa.",
        ));
    }
    v.push(Line::raw(""));
    v.push(heading(t, i18n::K_NOW, false));
    v.push(Line::styled(
        if on {
            "está na lista de --script"
        } else {
            "fora da lista de --script"
        },
        if on { t.ok() } else { t.dim() },
    ));
    v.push(Line::raw(""));
    v.push(heading(t, i18n::K_HOW, false));
    v.push(Line::raw(i18n::HOW_NSE));
    v
}

/// Opção que emite o token de um campo auxiliar (ex.: `tec` para `zombie`).
fn owner_of(o: &'static Opt) -> &'static Opt {
    if !o.helper {
        return o;
    }
    catalog::all()
        .iter()
        .find(|p| p.choices.iter().any(|c| c.arg_from == Some(o.id)))
        .unwrap_or(o)
}

fn opt_detail(app: &App, o: &'static Opt) -> Vec<Line<'static>> {
    let t = &app.theme;
    let v = &app.values;
    let mut out: Vec<Line> = vec![Line::styled(o.label.to_string(), t.bold())];
    let mut sub: Vec<Span> = Vec::new();
    match v.root_of(o) {
        Root::Hard => sub.push(badge(t, i18n::BADGE_ROOT, t.warn())),
        Root::Soft => sub.push(badge(t, i18n::BADGE_SOFT, t.warn())),
        Root::None => {}
    }
    if o.standalone {
        sub.push(badge(t, i18n::BADGE_STANDALONE, t.ok()));
    }
    if !o.flag.is_empty() {
        sub.push(Span::raw(" "));
        sub.push(Span::styled(o.flag.to_string(), t.flag()));
    }
    if !sub.is_empty() {
        out.push(Line::from(sub));
    }
    out.push(Line::raw(""));
    out.push(heading(t, i18n::K_WHAT, false));
    out.push(Line::raw(o.what.to_string()));
    if !o.when.is_empty() {
        out.push(Line::raw(""));
        out.push(heading(t, i18n::K_WHEN, false));
        out.push(Line::raw(o.when.to_string()));
    }
    if !o.caution.is_empty() {
        out.push(Line::raw(""));
        out.push(heading(t, i18n::K_CAUTION, true));
        out.push(Line::raw(o.caution.to_string()));
    }
    if o.kind == Kind::Choice {
        out.push(Line::raw(""));
        out.push(heading(t, i18n::K_VALUES, false));
        for c in &o.choices {
            let cur = c.id == v.get(o.id);
            let mut head = vec![
                Span::styled(if cur { "▸ " } else { "  " }, t.accent()),
                Span::styled(
                    c.label.to_string(),
                    if cur { t.accent() } else { t.normal() },
                ),
            ];
            if c.root == Root::Hard {
                head.push(Span::raw(" "));
                head.push(badge(t, "ADMIN", t.warn()));
            }
            out.push(Line::from(head));
            out.push(Line::styled(format!("  {}", c.what), t.dim()));
        }
    }
    if !o.examples.is_empty() {
        out.push(Line::raw(""));
        out.push(heading(t, i18n::K_EXAMPLES, false));
        for (a, b) in &o.examples {
            out.push(Line::from(vec![
                Span::styled(format!("{a:<18}"), t.flag()),
                Span::raw(" "),
                Span::styled(b.to_string(), t.dim()),
            ]));
        }
    }
    if matches!(o.kind, Kind::Text | Kind::Number)
        && !o.placeholder.is_empty()
        && !o.flag.is_empty()
        && !o.helper
        && o.fmt != Fmt::Raw
    {
        let sep = match o.fmt {
            Fmt::Cat => "",
            Fmt::Eq => "=",
            _ => " ",
        };
        out.push(Line::raw(""));
        out.push(heading(t, i18n::K_USE, false));
        out.push(Line::from(Span::styled(
            format!("{}{sep}{}", o.flag, o.placeholder),
            t.flag(),
        )));
    }
    // validação
    if o.id == "targets" {
        out.push(Line::raw(""));
        out.push(heading(t, i18n::K_VALIDATION, false));
        out.push(match validate::targets(v.text("targets")) {
            Ok(l) => Line::styled(format!("✔ {} alvo(s) válido(s)", l.len()), t.ok()),
            Err(e) => Line::styled(format!("✘ {e}"), t.err()),
        });
    } else if matches!(o.kind, Kind::Text | Kind::Number) {
        let err = if o.id == "extra" {
            validate::extra_args(v.get(o.id)).err()
        } else {
            validate::value(&o.validator, v.get(o.id)).err()
        };
        if let Some(e) = err {
            out.push(Line::raw(""));
            out.push(heading(t, i18n::K_PROBLEM, true));
            out.push(Line::styled(e, t.err()));
        }
    }
    // "neste momento"
    let owner = owner_of(o);
    let toks: Vec<String> = app
        .tokens()
        .iter()
        .filter(|k| k.opt == owner.id)
        .map(|k| k.display())
        .collect();
    out.push(Line::raw(""));
    out.push(heading(t, i18n::K_NOW, false));
    if toks.is_empty() {
        out.push(Line::styled(i18n::OFF_NOTE, t.faint()));
    } else {
        out.push(Line::from(
            toks.into_iter()
                .flat_map(|s| [Span::styled(s, t.flag()), Span::raw(" ")])
                .collect::<Vec<_>>(),
        ));
    }
    out.push(Line::raw(""));
    out.push(heading(t, i18n::K_HOW, false));
    out.push(Line::raw(match o.kind {
        Kind::Bool => i18n::HOW_BOOL,
        Kind::Choice => i18n::HOW_CHOICE,
        _ => i18n::HOW_TEXT,
    }));
    out
}
