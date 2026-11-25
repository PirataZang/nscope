//! Tela Ajuda: lista de tópicos à esquerda e o conteúdo do tópico escolhido à direita.

use super::{block, inner, kv_lines, wrap_spans};
use crate::app::{App, Hit};
use crate::i18n::{self, Help};
use crate::util::truncate;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthStr;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    let topics = i18n::help();
    let cur = app.cursor().min(topics.len() - 1);
    let left_w = topics.iter().map(|(n, _)| n.width()).max().unwrap_or(10) as u16 + 6;
    let [l, r] = Layout::horizontal([Constraint::Length(left_w), Constraint::Min(30)]).areas(area);

    f.render_widget(block(&t, "Tópicos"), l);
    let li = inner(l);
    let lines: Vec<Line> = topics
        .iter()
        .enumerate()
        .take(li.height as usize)
        .map(|(n, (name, _))| {
            app.hits.push((
                Rect {
                    x: li.x,
                    y: li.y + n as u16,
                    width: li.width,
                    height: 1,
                },
                Hit::HelpSection(n),
            ));
            let txt = truncate(&format!(" {name}"), li.width as usize);
            if n == cur {
                let pad = (li.width as usize).saturating_sub(txt.width());
                Line::styled(format!("{txt}{}", " ".repeat(pad)), t.selected())
            } else {
                Line::styled(txt, t.normal())
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines), li);

    let (name, content) = &topics[cur];
    let ri = inner(r);
    let w = ri.width as usize;
    let mut out: Vec<Line> = Vec::new();
    if cur == topics.len() - 1 {
        out.push(match &app.env.nmap {
            Ok(v) => Line::styled(format!("✔ nmap encontrado: {v}"), t.ok()),
            Err(_) => Line::styled("✘ O nmap não foi encontrado no PATH. Instale com:", t.err()),
        });
        out.push(Line::raw(""));
    }
    // itens seguidos formam uma tabela alinhada
    let mut batch: Vec<(Vec<Span<'static>>, Vec<Span<'static>>)> = Vec::new();
    let flush = |batch: &mut Vec<_>, out: &mut Vec<Line<'static>>| {
        if !batch.is_empty() {
            out.extend(kv_lines(batch, w, 24));
            batch.clear();
        }
    };
    for h in content {
        match h {
            Help::Item(k, d) => batch.push((
                vec![Span::styled(k.to_string(), t.flag())],
                vec![Span::raw(d.to_string())],
            )),
            other => {
                flush(&mut batch, &mut out);
                match other {
                    Help::Heading(s) => out.push(Line::styled(
                        s.to_uppercase(),
                        t.dim().add_modifier(Modifier::BOLD),
                    )),
                    Help::Para(s) => out.extend(
                        wrap_spans(&[Span::raw(s.to_string())], w)
                            .into_iter()
                            .map(Line::from),
                    ),
                    _ => out.push(Line::raw("")),
                }
            }
        }
    }
    flush(&mut batch, &mut out);

    app.detail_scroll = app.detail_scroll.min(out.len().saturating_sub(1));
    let more = out.len() > ri.height as usize + app.detail_scroll;
    let title = match (app.detail_scroll > 0, more) {
        (_, true) => format!("{name} (PgDn rola)"),
        (true, false) => format!("{name} (PgUp volta)"),
        _ => name.to_string(),
    };
    f.render_widget(block(&t, &title), r);
    f.render_widget(
        Paragraph::new(out).scroll((app.detail_scroll as u16, 0)),
        ri,
    );
}
