//! Cores: só as 16 do terminal (funciona em qualquer lugar). Com NO_COLOR, usa apenas negrito/inverso.

use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub color: bool,
}

impl Theme {
    pub fn from_env() -> Theme {
        // https://no-color.org: qualquer valor não vazio desliga as cores
        Theme {
            color: std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
        }
    }
    fn fg(&self, c: Color) -> Style {
        if self.color {
            Style::default().fg(c)
        } else {
            Style::default()
        }
    }
    pub fn normal(&self) -> Style {
        Style::default()
    }
    pub fn accent(&self) -> Style {
        self.fg(Color::Cyan).add_modifier(Modifier::BOLD)
    }
    pub fn flag(&self) -> Style {
        self.fg(Color::Magenta)
    }
    pub fn value(&self) -> Style {
        self.fg(Color::Cyan)
    }
    pub fn ok(&self) -> Style {
        self.fg(Color::Green)
    }
    pub fn warn(&self) -> Style {
        self.fg(Color::Yellow)
    }
    pub fn err(&self) -> Style {
        self.fg(Color::Red).add_modifier(Modifier::BOLD)
    }
    pub fn dim(&self) -> Style {
        if self.color {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        }
    }
    pub fn faint(&self) -> Style {
        self.dim()
    }
    pub fn bold(&self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }
    pub fn program(&self) -> Style {
        self.fg(Color::Green).add_modifier(Modifier::BOLD)
    }
    /// Seleção em vídeo reverso (fundo de destaque, texto escuro).
    pub fn selected(&self) -> Style {
        if self.color {
            Style::default().bg(Color::Cyan).fg(Color::Black)
        } else {
            Style::default().add_modifier(Modifier::REVERSED)
        }
    }
    pub fn tab_on(&self) -> Style {
        self.selected().add_modifier(Modifier::BOLD)
    }
    pub fn border(&self) -> Style {
        self.dim()
    }
}
