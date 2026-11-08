//! Tela Ajuda: como usar, atalhos, estados, técnicas, glossário, uso responsável e instalação.

use super::{block, inner};
use crate::app::App;
use crate::i18n::{self, Help};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    f.render_widget(block(&t, "Ajuda"), area);
    let mut lines: Vec<Line> = Vec::new();
    for h in i18n::help() {
        match h {
            Help::Heading(s) => {
                lines.push(Line::styled(s, t.accent().add_modifier(Modifier::BOLD)))
            }
            Help::Para(s) => lines.push(Line::raw(s)),
            Help::Item(k, d) => lines.push(Line::from(vec![
                Span::styled(format!("{k}: "), t.flag()),
                Span::raw(d),
            ])),
            Help::Blank => lines.push(Line::raw("")),
        }
    }
    match &app.env.nmap {
        Ok(v) => lines.push(Line::styled(format!("✔ Encontrado: {v}"), t.ok())),
        Err(_) => lines.push(Line::styled(
            "✘ O nmap não foi encontrado no PATH. Instale com:",
            t.err(),
        )),
    }
    for (os, cmd) in i18n::install_lines() {
        lines.push(Line::from(vec![
            Span::styled(format!("{os}: "), t.flag()),
            Span::raw(cmd),
        ]));
    }
    lines.push(Line::styled(
        "Sem o nmap você ainda pode montar e copiar comandos (y).",
        t.dim(),
    ));
    app.detail_scroll = app.detail_scroll.min(lines.len().saturating_sub(1));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll as u16, 0)),
        inner(area),
    );
}
