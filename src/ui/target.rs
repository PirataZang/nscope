//! Tela Alvo: o campo principal em destaque, as outras formas de indicar alvos e os formatos aceitos.

use super::{block, inner, options};
use crate::app::{App, Hit};
use crate::nmap::analyze;
use crate::nmap::catalog::{self, Section};
use crate::nmap::validate;
use crate::util::truncate;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthStr;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let [hero, rest] = Layout::vertical([Constraint::Length(5), Constraint::Min(6)]).areas(area);
    draw_main(f, app, hero);

    let [l, r] = options::split(rest);
    let n = catalog::section(Section::Alvo).count() as u16;
    let [list, formats] = Layout::vertical([
        Constraint::Length((n + 1).min(l.height / 2)),
        Constraint::Min(3),
    ])
    .areas(l);
    options::draw_list(f, app, list, "Mais opções de alvo (opcional)", 1);
    options::draw_detail(f, app, r);

    let t = app.theme;
    f.render_widget(block(&t, "Formatos aceitos"), formats);
    let fi = inner(formats);
    let w = fi.width as usize;
    let mut lines: Vec<Line> = Vec::new();
    if let Some(o) = catalog::get("targets") {
        for (a, b) in &o.examples {
            lines.push(Line::from(vec![
                Span::styled(format!("{a:<18}"), t.flag()),
                Span::styled(truncate(b, w.saturating_sub(18)), t.dim()),
            ]));
        }
    }
    lines.push(Line::styled(
        truncate("Até 64 alvos; nenhum pode começar com \"-\".", w),
        t.dim(),
    ));
    f.render_widget(Paragraph::new(lines), fi);
}

/// Caixa de cima: o que será escaneado, com a validação logo abaixo do valor.
fn draw_main(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    let sel = app.cursor() == 0;
    f.render_widget(
        block(&t, "O que escanear").border_style(if sel { t.accent() } else { t.border() }),
        area,
    );
    let i = inner(area);
    app.hits.push((i, Hit::Row(0)));
    let w = i.width as usize;
    let value = app.values.text("targets").to_string();

    let label = Span::styled("Alvos  ", t.dim());
    let first = match app.edit.as_ref().filter(|e| e.id == "targets") {
        Some(e) => {
            let (b, a, af) = e.input.view(w.saturating_sub(8));
            Line::from(vec![
                label,
                Span::raw(b),
                Span::styled(a, t.selected()),
                Span::raw(af),
            ])
        }
        None if value.is_empty() => Line::from(vec![
            label,
            Span::styled(
                "(vazio) pressione Enter e digite, ex.: scanme.nmap.org",
                t.dim(),
            ),
        ]),
        None => {
            let shown = truncate(&value, w.saturating_sub(8));
            let pad = w.saturating_sub(7 + shown.width());
            Line::from(vec![
                label,
                Span::styled(
                    format!("{shown}{}", " ".repeat(if sel { pad } else { 0 })),
                    if sel { t.selected() } else { t.value() },
                ),
            ])
        }
    };

    let status = match validate::targets(&value) {
        _ if value.is_empty() => Line::styled(
            "Um IP, um nome de máquina ou uma rede inteira. Veja os formatos abaixo.",
            t.dim(),
        ),
        Ok(l) => {
            let n = l.len();
            let what = if n == 1 {
                "alvo válido"
            } else {
                "alvos válidos"
            };
            Line::styled(format!("✔ {n} {what}"), t.ok())
        }
        Err(e) => Line::styled(truncate(&format!("✘ {e}"), w), t.err()),
    };

    let ext = analyze::external_targets(&app.values);
    let note = if !ext.is_empty() {
        Line::styled(
            truncate(
                &format!(
                    "⚠ Fora da rede local ({}): só escaneie com autorização do responsável.",
                    ext.join(", ")
                ),
                w,
            ),
            t.warn(),
        )
    } else if app.edit.is_some() {
        Line::styled("Enter confirma · Esc cancela · Ctrl+U apaga tudo", t.dim())
    } else {
        Line::styled("Enter edita · Del limpa · ↓ mais opções de alvo", t.dim())
    };
    f.render_widget(Paragraph::new(vec![first, status, note]), i);
}
