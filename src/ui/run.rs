//! Tela Execução: situação, progresso, comando e botões em uma tabela; saída do nmap com rolagem e cores.

use super::widgets::progress;
use super::{block, inner, kv_lines};
use crate::app::{App, Hit, LogKind, RunState};
use crate::i18n;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthStr;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    let i = inner(area);
    let secs = app.elapsed().as_secs();
    let status: Vec<Span> = match &app.run_state {
        RunState::Idle => vec![Span::styled("● ", t.warn()), Span::raw(i18n::RUN_IDLE)],
        RunState::Running => vec![Span::styled("● ", t.ok()), Span::raw(i18n::RUN_RUNNING)],
        RunState::Cancelled => vec![Span::styled("● ", t.warn()), Span::raw(i18n::RUN_CANCELLED)],
        RunState::Done => vec![
            Span::styled("✔ ", t.ok()),
            Span::raw(if app.result.is_some() && !app.run_standalone {
                format!(
                    "Concluído em {}. Veja os Resultados (7).",
                    progress::mmss(secs)
                )
            } else {
                i18n::RUN_DONE.to_string()
            }),
        ],
        RunState::Failed(e) => vec![Span::styled(format!("✘ {e}"), t.err())],
    };
    let width = (i.width as usize).saturating_sub(44).clamp(10, 50);
    let bar = match (&app.run_progress, &app.run_state) {
        (Some(p), RunState::Running | RunState::Cancelled) => {
            let rem = p
                .remaining
                .as_deref()
                .map_or(String::new(), |r| format!(" · restam {r}"));
            format!("{}{rem}", progress::bar(p.percent, width, secs))
        }
        (_, RunState::Done) if !app.run_standalone => progress::bar(100.0, width, secs),
        (_, RunState::Running) => progress::indeterminate(width, app.elapsed().as_millis(), secs),
        _ => progress::bar(0.0, width, secs),
    };
    let cmd = if app.run_command.is_empty() {
        app.command_text()
    } else {
        app.run_command.clone()
    };
    let cmd_label = if app.run_command.is_empty() {
        "Vai rodar"
    } else {
        "Comando"
    };
    let rows = vec![
        (vec![Span::styled("Situação", t.dim())], status),
        (
            vec![Span::styled("Progresso", t.dim())],
            vec![Span::styled(bar, t.value())],
        ),
        (
            vec![Span::styled(cmd_label, t.dim())],
            vec![Span::styled(
                crate::util::truncate(&format!("$ {cmd}"), (i.width as usize).saturating_sub(11)),
                t.normal(),
            )],
        ),
    ];
    let mut lines = kv_lines(&rows, i.width as usize, 9);
    let by = i.y + lines.len() as u16;
    let btn_run = " ▶ Executar (r) ";
    let btn_cancel = " ■ Cancelar (c) ";
    let pad = " ".repeat(11);
    lines.push(Line::from(vec![
        Span::raw(pad.clone()),
        Span::styled(
            btn_run,
            if app.is_running() {
                t.dim()
            } else {
                t.tab_on()
            },
        ),
        Span::raw("  "),
        Span::styled(
            btn_cancel,
            if app.is_running() {
                t.selected()
            } else {
                t.dim()
            },
        ),
    ]));
    let top_h = (lines.len() as u16 + 2).min(area.height / 2);
    let [top, logbox] =
        Layout::vertical([Constraint::Length(top_h), Constraint::Min(4)]).areas(area);
    let border = match app.run_state {
        RunState::Running => t.ok(),
        RunState::Failed(_) => t.err(),
        _ => t.border(),
    };
    f.render_widget(block(&t, "Andamento").border_style(border), top);
    f.render_widget(Paragraph::new(lines), inner(top));
    let x0 = i.x + pad.width() as u16;
    app.hits.push((
        Rect {
            x: x0,
            y: by,
            width: btn_run.width() as u16,
            height: 1,
        },
        Hit::Run,
    ));
    app.hits.push((
        Rect {
            x: x0 + btn_run.width() as u16 + 2,
            y: by,
            width: btn_cancel.width() as u16,
            height: 1,
        },
        Hit::Cancel,
    ));

    let opened = app.log.iter().filter(|l| l.kind == LogKind::Open).count();
    let mut title = format!("Saída do nmap · {} linhas", app.log.len());
    if opened > 0 {
        title.push_str(&format!(
            " · {opened} {}",
            if opened == 1 {
                "porta aberta"
            } else {
                "portas abertas"
            }
        ));
    }
    if app.log_back > 0 {
        title.push_str(" · rolada (End volta ao fim)");
    }
    f.render_widget(block(&t, &title), logbox);
    let li = inner(logbox);
    if app.log.is_empty() {
        let msg = match &app.env.nmap {
            Err(_) => i18n::MSG_NO_NMAP,
            Ok(_) => i18n::LOG_EMPTY,
        };
        f.render_widget(Paragraph::new(Line::styled(msg, t.dim())), li);
        return;
    }
    let h = li.height as usize;
    let end = app.log.len().saturating_sub(app.log_back);
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = app
        .log
        .iter()
        .skip(start)
        .take(end - start)
        .map(|l| {
            let st = match l.kind {
                LogKind::Open => t.ok(),
                LogKind::Warn => t.warn(),
                LogKind::Head => t.accent(),
                LogKind::Normal => t.normal(),
            };
            Line::styled(crate::util::truncate(&l.text, li.width as usize), st)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), li);
}
