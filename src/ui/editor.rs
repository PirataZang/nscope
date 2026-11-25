//! Tela Editar: o comando inteiro num bloco editável em cima e, embaixo, a explicação de tudo.
//! O texto digitado é lido a cada tecla e vira as opções das outras abas (sem passar por shell).

use super::command::{finding_lines, pieces_lines, status_spans, summary_rows};
use super::{block, heading, inner, kv_lines, wrap_spans};
use crate::app::{App, Hit};
use crate::nmap::analyze::Finding;
use crate::nmap::command::Token;
use crate::ui::theme::Theme;
use crate::ui::widgets::input::TextInput;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthChar;

/// Texto em edição quebrado em linhas de `width` colunas, com o cursor destacado.
fn input_lines(t: &Theme, input: &TextInput, width: usize) -> Vec<Line<'static>> {
    let width = width.max(4);
    let mut chars: Vec<char> = input.value().chars().collect();
    let cur = input.cursor().min(chars.len());
    if cur == chars.len() {
        chars.push(' ');
    }
    let mut lines = vec![vec![Span::styled("$ ", t.ok())]];
    let mut w = 2;
    for (n, c) in chars.into_iter().enumerate() {
        let cw = c.width().unwrap_or(0);
        if w + cw > width {
            lines.push(vec![Span::raw("  ")]);
            w = 2;
        }
        let st = if n == cur { t.selected() } else { t.normal() };
        lines
            .last_mut()
            .expect("sempre há uma linha")
            .push(Span::styled(c.to_string(), st));
        w += cw;
    }
    lines.into_iter().map(Line::from).collect()
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect, tokens: &[Token], findings: &[Finding]) {
    let t = app.theme;
    let w = area.width.saturating_sub(2) as usize;
    let editing = app.cmd_edit.is_some();

    // bloco de cima: o comando
    let mut top: Vec<Line> = match &app.cmd_edit {
        Some(e) => input_lines(&t, &e.input, w),
        None => wrap_spans(&super::command::command_spans(&t, tokens), w)
            .into_iter()
            .map(Line::from)
            .collect(),
    };
    top.truncate(6);
    top.push(Line::raw(""));
    top.push(match app.cmd_edit.as_ref().and_then(|e| e.error.as_ref()) {
        Some(err) => Line::from(
            wrap_spans(&[Span::styled(format!("✘ {err}"), t.err())], w)
                .into_iter()
                .next()
                .unwrap_or_default(),
        ),
        None if editing => Line::from(Span::styled(
            "✔ Comando entendido. Enter aplica · Esc desfaz tudo",
            t.ok(),
        )),
        None => Line::from(vec![
            Span::styled(" Enter ", t.tab_on()),
            Span::styled(
                " editar este comando: apague (Ctrl+U), digite ou cole outro",
                t.dim(),
            ),
        ]),
    });
    let top_h = (top.len() as u16 + 2).min(area.height / 2);
    let [cmd_box, explain] =
        Layout::vertical([Constraint::Length(top_h), Constraint::Min(4)]).areas(area);
    let title = if editing {
        "Comando (editando)"
    } else {
        "Comando"
    };
    f.render_widget(
        block(&t, title).border_style(if editing { t.accent() } else { t.border() }),
        cmd_box,
    );
    f.render_widget(Paragraph::new(top), inner(cmd_box));
    if !editing {
        app.hits.push((inner(cmd_box), Hit::EditCmd));
    }

    // bloco de baixo: tudo o que o comando faz
    let ei = inner(explain);
    let ew = ei.width as usize;
    let mut lines: Vec<Line> = Vec::new();
    lines.push(heading(&t, "Cada parte do comando", false));
    lines.extend(pieces_lines(&t, tokens, ew));
    if !findings.is_empty() {
        lines.push(Line::raw(""));
        lines.push(heading(&t, &super::command::warnings_title(findings), true));
        for fd in findings {
            lines.extend(finding_lines(&t, fd, ew, false));
        }
    }
    lines.push(Line::raw(""));
    lines.push(heading(&t, "Resumo", false));
    let mut rows = summary_rows(app);
    rows.push((
        vec![Span::styled("Situação", t.dim())],
        status_spans(&t, findings),
    ));
    lines.extend(kv_lines(&rows, ew, 14));
    lines.push(Line::raw(""));
    lines.push(heading(&t, "Como esta aba funciona", false));
    let tips = [
        (
            "Digite",
            "o comando como no terminal. O nmap e o sudo do começo são opcionais.",
        ),
        (
            "Opções",
            "as que o nscope conhece viram opções das outras abas (Configurar, Alvo) e ganham explicação.",
        ),
        (
            "Desconhecidas",
            "vão para Flags extras e seguem para o nmap como estão. Se tiverem valor, use --opcao=valor.",
        ),
        (
            "Sem shell",
            "; & | $ < > ( ) e o acento grave não são aceitos: nada aqui passa por um shell.",
        ),
    ];
    let rows: Vec<_> = tips
        .iter()
        .map(|(k, v)| {
            (
                vec![Span::styled(k.to_string(), t.flag())],
                vec![Span::styled(v.to_string(), t.dim())],
            )
        })
        .collect();
    lines.extend(kv_lines(&rows, ew, 14));

    app.detail_scroll = app.detail_scroll.min(lines.len().saturating_sub(1));
    let more = lines.len() > ei.height as usize + app.detail_scroll;
    let title = match (app.detail_scroll > 0, more) {
        (_, true) => "O que este comando faz (↑↓ rola)",
        (true, false) => "O que este comando faz (↑ volta)",
        _ => "O que este comando faz",
    };
    f.render_widget(block(&t, title), explain);
    f.render_widget(
        Paragraph::new(lines).scroll((app.detail_scroll as u16, 0)),
        ei,
    );
}
