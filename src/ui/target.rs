//! Tela Alvo: opções de alvo, validação ao vivo e formatos aceitos.

use super::{block, inner, options};
use crate::app::App;
use crate::nmap::catalog::{self, Section};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let [l, r] = options::split(area);
    let n = catalog::section(Section::Alvo).count() as u16;
    let [list, formats] = Layout::vertical([
        Constraint::Length((n + 2).min(l.height / 2)),
        Constraint::Min(3),
    ])
    .areas(l);
    options::draw_list(f, app, list, Section::Alvo.title());
    options::draw_detail(f, app, r);

    let t = app.theme;
    f.render_widget(block(&t, "Formatos aceitos"), formats);
    let mut lines: Vec<Line> = Vec::new();
    if let Some(o) = catalog::get("targets") {
        for (a, b) in &o.examples {
            lines.push(Line::from(vec![
                Span::styled(format!("{a:<19}"), t.flag()),
                Span::styled(b.to_string(), t.dim()),
            ]));
        }
    }
    lines.push(Line::styled(
        "Máx. 64 alvos, 253 caracteres cada; não pode começar com \"-\".",
        t.dim(),
    ));
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner(formats),
    );
}
