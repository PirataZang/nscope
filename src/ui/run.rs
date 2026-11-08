//! Tela Execução: status, barra de progresso, saída do nmap com rolagem e cores.

use super::widgets::progress;
use super::{block, inner};
use crate::app::{App, Hit, LogKind, RunState};
use crate::i18n;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthStr;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let t = app.theme;
    let [top, logbox] = Layout::vertical([Constraint::Length(7), Constraint::Min(4)]).areas(area);
    f.render_widget(block(&t, "Andamento"), top);
    let i = inner(top);
    let status = match &app.run_state {
        RunState::Idle => Line::from(vec![
            Span::styled("● ", t.warn()),
            Span::raw(i18n::RUN_IDLE),
        ]),
        RunState::Running => Line::from(vec![
            Span::styled("● ", t.ok()),
            Span::raw(i18n::RUN_RUNNING),
        ]),
        RunState::Cancelled => Line::from(vec![
            Span::styled("● ", t.warn()),
            Span::raw(i18n::RUN_CANCELLED),
        ]),
        RunState::Done => Line::from(vec![
            Span::styled("✔ ", t.ok()),
            Span::raw(if app.result.is_some() && !app.run_standalone {
                "Concluído. Veja os Resultados (6)."
            } else {
                i18n::RUN_DONE
            }),
        ]),
        RunState::Failed(e) => Line::from(vec![
            Span::styled("✘ ", t.err()),
            Span::styled(e.clone(), t.err()),
        ]),
    };
    let secs = app.elapsed().as_secs();
    let width = (i.width as usize).saturating_sub(44).clamp(10, 40);
    let bar = match (&app.run_progress, &app.run_state) {
        (Some(p), RunState::Running | RunState::Cancelled) => {
            let rem = p
                .remaining
                .as_deref()
                .map_or(String::new(), |r| format!("  restam {r}"));
            format!("{}{rem}", progress::bar(p.percent, width, secs))
        }
        (_, RunState::Done) if !app.run_standalone => progress::bar(100.0, width, secs),
        (_, RunState::Running) => progress::indeterminate(width, app.elapsed().as_millis(), secs),
        _ => progress::bar(0.0, width, secs),
    };
    let cmd = if app.run_command.is_empty() {
        String::new()
    } else {
        crate::util::truncate(&app.run_command, i.width as usize - 2)
    };
    let btn_run = " ▶ Executar (r) ";
    let btn_cancel = " ■ Cancelar (c) ";
    let lines = vec![
        status,
        Line::raw(""),
        Line::styled(bar, t.value()),
        Line::styled(format!("$ {cmd}"), t.dim()),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                btn_run,
                if app.is_running() {
                    t.dim()
                } else {
                    t.tab_on()
                },
            ),
            Span::raw(" "),
            Span::styled(
                btn_cancel,
                if app.is_running() {
                    t.selected()
                } else {
                    t.dim()
                },
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), i);
    let by = i.y + 5;
    app.hits.push((
        Rect {
            x: i.x,
            y: by,
            width: btn_run.width() as u16,
            height: 1,
        },
        Hit::Run,
    ));
    app.hits.push((
        Rect {
            x: i.x + btn_run.width() as u16 + 1,
            y: by,
            width: btn_cancel.width() as u16,
            height: 1,
        },
        Hit::Cancel,
    ));

    let title = if app.log_back > 0 {
        "Saída do nmap (rolada; End volta ao fim)"
    } else {
        "Saída do nmap"
    };
    f.render_widget(block(&t, title), logbox);
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
