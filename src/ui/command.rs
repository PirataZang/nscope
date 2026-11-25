//! Tela Comando: resumo (comando, em palavras simples, visibilidade, situação), cada pedaço e avisos.

use super::{block, inner, kv_lines, token_spans, wrap_spans};
use crate::app::{App, Hit};
use crate::i18n;
use crate::nmap::analyze::{Finding, Level};
use crate::nmap::command::{self, Token};
use crate::nmap::noise;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

/// Spans do comando inteiro (`$ nmap ...`), para caber numa célula de tabela.
pub fn command_spans(t: &Theme, tokens: &[Token]) -> Vec<Span<'static>> {
    let mut v = vec![
        Span::styled("$ ", t.ok()),
        Span::styled("nmap", t.program()),
    ];
    for k in tokens {
        v.push(Span::raw(" "));
        // valores com espaço (entre aspas) não devem quebrar no meio
        v.extend(
            token_spans(t, k)
                .into_iter()
                .map(|s| Span::styled(s.content.replace(' ', "\u{a0}"), s.style)),
        );
    }
    v
}

/// Linhas "Na prática" e "Visibilidade" (usadas aqui e na aba Editar).
pub fn summary_rows(app: &App) -> Vec<(Vec<Span<'static>>, Vec<Span<'static>>)> {
    let t = app.theme;
    let nz = noise::estimate(&app.values);
    let mut vis = vec![
        Span::styled(noise::meter(nz.level), t.warn()),
        Span::raw(format!(" {}", nz.label)),
    ];
    if !nz.reasons.is_empty() {
        vis.push(Span::styled(
            format!(" · {}", nz.reasons.join(", ")),
            t.dim(),
        ));
    }
    vec![
        (
            vec![Span::styled("Na prática", t.dim())],
            vec![Span::raw(command::describe(&app.values))],
        ),
        (vec![Span::styled("Visibilidade", t.dim())], vis),
    ]
}

/// Situação do comando em uma linha: pronto, pronto com avisos ou bloqueado.
pub fn status_spans(t: &Theme, findings: &[Finding]) -> Vec<Span<'static>> {
    let errs = findings.iter().filter(|x| x.level == Level::Error).count();
    let warns = findings.iter().filter(|x| x.level == Level::Warn).count();
    if errs > 0 {
        vec![Span::styled(
            format!(
                "✘ {errs} {} impede{} a execução. Veja os avisos.",
                if errs == 1 { "problema" } else { "problemas" },
                if errs == 1 { "" } else { "m" }
            ),
            t.err(),
        )]
    } else if warns > 0 {
        vec![Span::styled(
            format!(
                "⚠ Pode executar (r), mas leia {} antes.",
                if warns == 1 {
                    "o aviso".to_string()
                } else {
                    format!("os {warns} avisos")
                }
            ),
            t.warn(),
        )]
    } else {
        vec![Span::styled("✔ Pronto para executar (r).", t.ok())]
    }
}

/// Tabela "pedaço → o que faz".
pub fn pieces_lines(t: &Theme, tokens: &[Token], width: usize) -> Vec<Line<'static>> {
    let mut rows = vec![(
        vec![Span::styled("nmap", t.program())],
        vec![Span::raw("o programa que faz o scan")],
    )];
    for k in tokens {
        rows.push((token_spans(t, k), vec![Span::raw(k.explain.clone())]));
    }
    kv_lines(&rows, width, 22)
}

fn icon(t: &Theme, l: Level) -> (&'static str, ratatui::style::Style) {
    match l {
        Level::Error => ("✘", t.err()),
        Level::Warn => ("⚠", t.warn()),
        Level::Info => ("ℹ", t.accent()),
    }
}

/// Título do painel de avisos com a contagem por nível.
pub fn warnings_title(findings: &[Finding]) -> String {
    let count = |l| findings.iter().filter(|x| x.level == l).count();
    let mut parts = Vec::new();
    for (l, one, many) in [
        (Level::Error, "erro", "erros"),
        (Level::Warn, "aviso", "avisos"),
        (Level::Info, "dica", "dicas"),
    ] {
        match count(l) {
            0 => {}
            1 => parts.push(format!("1 {one}")),
            n => parts.push(format!("{n} {many}")),
        }
    }
    if parts.is_empty() {
        i18n::PANEL_WARNINGS.to_string()
    } else {
        format!("{} · {}", i18n::PANEL_WARNINGS, parts.join(" · "))
    }
}

/// Um aviso em linhas com recuo: ícone na primeira, texto alinhado nas seguintes.
pub fn finding_lines(t: &Theme, fd: &Finding, width: usize, sel: bool) -> Vec<Line<'static>> {
    let (ic, st) = icon(t, fd.level);
    let mut body = vec![Span::styled(
        fd.msg.clone(),
        if sel { t.selected() } else { t.normal() },
    )];
    if fd.opt.is_some() {
        body.push(Span::styled(if sel { " ↵ ir" } else { "" }, t.accent()));
    }
    wrap_spans(&body, width.saturating_sub(2))
        .into_iter()
        .enumerate()
        .map(|(n, l)| {
            let mut v = vec![if n == 0 {
                Span::styled(format!("{ic} "), st)
            } else {
                Span::raw("  ")
            }];
            v.extend(l);
            Line::from(v)
        })
        .collect()
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect, tokens: &[Token], findings: &[Finding]) {
    let t = app.theme;
    let w = area.width.saturating_sub(2) as usize;
    let mut rows = vec![(
        vec![Span::styled("Comando", t.dim())],
        command_spans(&t, tokens),
    )];
    rows.extend(summary_rows(app));
    rows.push((
        vec![Span::styled("Situação", t.dim())],
        status_spans(&t, findings),
    ));
    let top_lines = kv_lines(&rows, w, 14);
    let top_h = (top_lines.len() as u16 + 2).min(area.height / 2 + 1);
    let [top, bottom] =
        Layout::vertical([Constraint::Length(top_h), Constraint::Min(4)]).areas(area);
    let errs = findings.iter().any(|x| x.level == Level::Error);
    f.render_widget(
        block(&t, "Resumo").border_style(if errs { t.err() } else { t.border() }),
        top,
    );
    f.render_widget(Paragraph::new(top_lines), inner(top));

    let [pieces, warns] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(bottom);
    let title = if app.pieces_scroll > 0 {
        format!("{} (PgUp volta ao topo)", i18n::PANEL_PIECES)
    } else {
        i18n::PANEL_PIECES.to_string()
    };
    f.render_widget(block(&t, &title), pieces);
    let pl = pieces_lines(&t, tokens, inner(pieces).width as usize);
    app.pieces_scroll = app.pieces_scroll.min(pl.len().saturating_sub(1));
    f.render_widget(
        Paragraph::new(pl).scroll((app.pieces_scroll as u16, 0)),
        inner(pieces),
    );

    f.render_widget(block(&t, &warnings_title(findings)), warns);
    let wi = inner(warns);
    let ww = wi.width as usize;
    if findings.is_empty() {
        let ok = vec![Span::styled(
            "✔ Nenhum problema encontrado. O comando está pronto para executar (r).",
            t.ok(),
        )];
        let lines: Vec<Line> = wrap_spans(&ok, ww).into_iter().map(Line::from).collect();
        f.render_widget(Paragraph::new(lines), wi);
        return;
    }
    let cur = app.cursor().min(findings.len() - 1);
    let blocks: Vec<Vec<Line>> = findings
        .iter()
        .enumerate()
        .map(|(n, fd)| finding_lines(&t, fd, ww, n == cur))
        .collect();
    // rola o mínimo para o aviso selecionado caber
    let key = app.list_key();
    let mut first = app.list_offset[key].min(cur);
    while first < cur
        && blocks[first..=cur].iter().map(Vec::len).sum::<usize>() > wi.height as usize
    {
        first += 1;
    }
    app.list_offset[key] = first;
    let mut lines: Vec<Line> = Vec::new();
    let mut y = 0u16;
    for (n, b) in blocks.into_iter().enumerate().skip(first) {
        let h = b.len() as u16;
        if y + h > wi.height {
            break;
        }
        app.hits.push((
            Rect {
                x: wi.x,
                y: wi.y + y,
                width: wi.width,
                height: h,
            },
            Hit::Finding(n),
        ));
        lines.extend(b);
        y += h;
    }
    f.render_widget(Paragraph::new(lines), wi);
}
