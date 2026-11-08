//! Tela Comando: comando final, "em palavras simples", ruído, cada pedaço e avisos com atalho.

use super::{block, command_lines, heading, inner, token_spans};
use crate::app::{App, Hit};
use crate::i18n;
use crate::nmap::analyze::{Finding, Level};
use crate::nmap::command::{self, Token};
use crate::nmap::noise;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect, tokens: &[Token], findings: &[Finding]) {
    let t = app.theme;
    let nz = noise::estimate(&app.values);
    let desc = command::describe(&app.values);
    let top_inner_w = area.width.saturating_sub(2) as usize;
    let cmd = command_lines(&t, tokens, top_inner_w);
    let desc_h = (desc.chars().count() / top_inner_w.max(1) + 1).min(4);
    let top_h = (cmd.len() + desc_h + 3 + 2).min(area.height as usize / 2 + 2) as u16;
    let [top, bottom] =
        Layout::vertical([Constraint::Length(top_h), Constraint::Min(4)]).areas(area);

    let errs = findings.iter().any(|x| x.level == Level::Error);
    f.render_widget(
        block(&t, i18n::PANEL_COMMAND).border_style(if errs { t.err() } else { t.border() }),
        top,
    );
    let mut lines: Vec<Line> = cmd;
    lines.push(Line::from(vec![
        Span::styled("Em palavras simples: ", t.dim()),
        Span::raw(desc),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Visibilidade estimada (didática): ", t.dim()),
        Span::styled(noise::meter(nz.level), t.warn()),
        Span::raw(format!(" {}", nz.label)),
        Span::styled(
            if nz.reasons.is_empty() {
                String::new()
            } else {
                format!(" ({})", nz.reasons.join(", "))
            },
            t.dim(),
        ),
    ]));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner(top));

    let [pieces, warns] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).areas(bottom);
    f.render_widget(block(&t, i18n::PANEL_PIECES), pieces);
    let mut pl: Vec<Line> = vec![Line::from(vec![
        Span::styled("nmap", t.program()),
        Span::styled("  o programa que faz o scan", t.dim()),
    ])];
    for k in tokens {
        let mut spans = token_spans(&t, k);
        spans.push(Span::styled(format!("  {}", k.explain), t.dim()));
        pl.push(Line::from(spans));
    }
    app.pieces_scroll = app.pieces_scroll.min(pl.len().saturating_sub(1));
    f.render_widget(
        Paragraph::new(pl)
            .wrap(Wrap { trim: false })
            .scroll((app.pieces_scroll as u16, 0)),
        inner(pieces),
    );

    f.render_widget(
        block(
            &t,
            &format!("{} ({})", i18n::PANEL_WARNINGS, findings.len()),
        ),
        warns,
    );
    let wi = inner(warns);
    if findings.is_empty() {
        f.render_widget(
            Paragraph::new(Line::styled(
                "✔ Nenhum problema encontrado. O comando está pronto para executar (r).",
                t.ok(),
            ))
            .wrap(Wrap { trim: false }),
            wi,
        );
        return;
    }
    let cur = app.cursor().min(findings.len() - 1);
    // cada aviso ocupa linhas variáveis; renderiza a partir do aviso selecionado quando não cabe
    let mut lines: Vec<Line> = Vec::new();
    let mut y = 0u16;
    let key = app.list_key();
    let start = app.list_offset[key].min(cur);
    let mut first = start;
    // garante que o selecionado caiba: avança o início até caber
    loop {
        let used: usize = findings[first..=cur]
            .iter()
            .map(|x| wrapped(&x.msg, wi.width as usize - 2))
            .sum();
        if used <= wi.height as usize || first == cur {
            break;
        }
        first += 1;
    }
    app.list_offset[key] = first;
    for (n, fd) in findings.iter().enumerate().skip(first) {
        let h = wrapped(&fd.msg, wi.width as usize - 2) as u16;
        if y + h > wi.height {
            break;
        }
        let (ic, st) = match fd.level {
            Level::Error => ("✘", t.err()),
            Level::Warn => ("⚠", t.warn()),
            Level::Info => ("ℹ", t.accent()),
        };
        let sel = n == cur;
        let go = if fd.opt.is_some() && sel {
            " ↵ ir"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{ic} "), st),
            Span::styled(fd.msg.clone(), if sel { t.selected() } else { t.normal() }),
            Span::styled(go, t.accent()),
        ]));
        app.hits.push((
            Rect {
                x: wi.x,
                y: wi.y + y,
                width: wi.width,
                height: h,
            },
            Hit::Finding(n),
        ));
        y += h;
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), wi);
    let _ = heading;
}

fn wrapped(msg: &str, width: usize) -> usize {
    crate::util::wrap(&format!("{msg} ↵ ir"), width.max(8))
        .len()
        .max(1)
}
