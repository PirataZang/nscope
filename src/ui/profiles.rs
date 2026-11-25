//! Tela Perfis: lista de perfis prontos e, ao lado, descrição, ruído estimado e comando equivalente.

use super::{badge, block, command_lines, heading, inner, token_spans};
use crate::app::{App, Hit};
use crate::i18n;
use crate::nmap::catalog::Root;
use crate::nmap::command;
use crate::nmap::noise;
use crate::nmap::profiles::{self, PROFILES};
use crate::util::truncate;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let [l, r] = super::options::split(area);
    let t = app.theme;
    f.render_widget(block(&t, "Perfis prontos"), l);
    let i = inner(l);
    let cur = app.cursor().min(PROFILES.len() - 1);
    let key = app.list_key();
    let off = super::widgets::list::scroll_offset(
        app.list_offset[key],
        cur,
        i.height as usize,
        PROFILES.len(),
    );
    app.list_offset[key] = off;
    let w = i.width as usize;
    let active = profiles::active(&app.values);
    let mut lines = Vec::new();
    for (n, p) in PROFILES
        .iter()
        .enumerate()
        .skip(off)
        .take(i.height as usize)
    {
        app.hits.push((
            Rect {
                x: i.x,
                y: i.y + (n - off) as u16,
                width: i.width,
                height: 1,
            },
            Hit::Profile(n),
        ));
        let on = active == Some(n);
        let mark = if n == 0 {
            "    "
        } else if on {
            "[x] "
        } else {
            "[ ] "
        };
        let star = if p.recommended { "★ " } else { "" };
        let left = format!("{mark}{star}{}", p.name);
        let right = noise::meter(p.noise);
        let left = truncate(&left, w.saturating_sub(right.width() + 2));
        let pad = w.saturating_sub(left.width() + right.width() + 1);
        let txt = format!("{left}{} {right}", " ".repeat(pad));
        lines.push(Line::styled(
            txt,
            if n == cur {
                t.selected()
            } else if on {
                t.ok()
            } else {
                t.normal()
            },
        ));
    }
    f.render_widget(Paragraph::new(lines), i);

    // detalhes do perfil selecionado (calculados sobre os valores que ele aplicaria)
    let p = &PROFILES[cur];
    let v = profiles::apply(p, &app.values);
    let toks = command::build(&v);
    let nz = noise::estimate(&v);
    let needs_admin = crate::nmap::catalog::all()
        .iter()
        .any(|o| !o.helper && v.visible(o) && v.is_set(o) && v.root_of(o) == Root::Hard);
    f.render_widget(block(&t, "Detalhes"), r);
    let ri = inner(r);
    let mut out: Vec<Line> = vec![Line::from(vec![
        Span::styled(
            format!("{}{}", if p.recommended { "★ " } else { "" }, p.name),
            t.bold(),
        ),
        Span::raw("  "),
        if p.recommended {
            badge(&t, "RECOMENDADO", t.ok())
        } else {
            Span::raw("")
        },
    ])];
    out.push(Line::raw(p.short));
    out.push(Line::raw(""));
    out.push(heading(&t, i18n::K_WHEN, false));
    out.push(Line::raw(p.when));
    out.push(Line::raw(""));
    out.push(heading(&t, "Visibilidade estimada (didática)", false));
    out.push(Line::from(vec![
        Span::styled(noise::meter(nz.level), t.warn()),
        Span::raw(format!(" {}", nz.label)),
        Span::styled(
            if nz.reasons.is_empty() {
                String::new()
            } else {
                format!("  ({})", nz.reasons.join(", "))
            },
            t.dim(),
        ),
    ]));
    if needs_admin {
        out.push(Line::raw(""));
        out.push(heading(&t, "Privilégios", true));
        out.push(Line::styled(
            if app.env.privileged {
                "Usa opções que exigem administrador (você está como administrador)."
            } else {
                "Usa opções que exigem administrador: rode o nscope com sudo."
            },
            t.warn(),
        ));
    }
    out.push(Line::raw(""));
    out.push(heading(&t, "Comando equivalente", false));
    out.extend(command_lines(&t, &toks, ri.width as usize));
    out.push(Line::raw(""));
    out.push(heading(&t, "O que cada parte faz", false));
    let parts: Vec<_> = toks.iter().filter(|k| !k.is_target()).collect();
    if parts.is_empty() {
        out.push(Line::styled(
            "Nenhuma opção extra: o nmap usa tudo no padrão.",
            t.dim(),
        ));
    }
    for k in parts {
        let mut spans = token_spans(&t, k);
        spans.insert(0, Span::raw("• "));
        out.push(Line::from(spans));
        out.push(Line::styled(format!("  {}", k.explain), t.dim()));
    }
    out.push(Line::raw(""));
    out.push(if active == Some(cur) {
        Line::styled(
            "✔ Este é o perfil em uso. Mudar qualquer opção depois tira a marca [x].",
            t.ok(),
        )
    } else {
        Line::styled(
            "Enter aplica (mantém os alvos e restaura o resto ao padrão).",
            t.accent(),
        )
    });
    let max = out.len().saturating_sub(1);
    app.detail_scroll = app.detail_scroll.min(max);
    f.render_widget(
        Paragraph::new(out)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll as u16, 0)),
        ri,
    );
}
