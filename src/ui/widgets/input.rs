//! Campo de texto de uma linha: cursor, Unicode, edição básica. Enter/Esc ficam com quem usa.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_width::UnicodeWidthChar;

#[derive(Clone, Debug, Default)]
pub struct TextInput {
    value: String,
    /// Posição do cursor em caracteres (não bytes).
    cursor: usize,
}

impl TextInput {
    pub fn new(v: &str) -> Self {
        TextInput {
            value: v.to_string(),
            cursor: v.chars().count(),
        }
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    /// Posição do cursor, em caracteres.
    pub fn cursor(&self) -> usize {
        self.cursor
    }
    fn byte(&self, ci: usize) -> usize {
        self.value
            .char_indices()
            .nth(ci)
            .map_or(self.value.len(), |(i, _)| i)
    }
    fn len(&self) -> usize {
        self.value.chars().count()
    }
    /// Processa uma tecla de edição. `true` se foi consumida (e o texto pode ter mudado).
    pub fn handle(&mut self, k: KeyEvent) -> bool {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Char('u') if ctrl => {
                self.value.clear();
                self.cursor = 0;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.len(),
            KeyCode::Char(c)
                if !ctrl && !k.modifiers.contains(KeyModifiers::ALT) && !c.is_control() =>
            {
                let b = self.byte(self.cursor);
                self.value.insert(b, c);
                self.cursor += 1;
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let b = self.byte(self.cursor - 1);
                self.value.remove(b);
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < self.len() => {
                let b = self.byte(self.cursor);
                self.value.remove(b);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.len(),
            KeyCode::Backspace | KeyCode::Delete => {}
            _ => return false,
        }
        true
    }

    /// Texto visível em `width` colunas, dividido em (antes do cursor, caractere sob o cursor, depois).
    pub fn view(&self, width: usize) -> (String, String, String) {
        let chars: Vec<char> = self.value.chars().collect();
        let w = |c: &char| c.width().unwrap_or(0);
        let mut start = 0;
        while start < self.cursor
            && chars[start..self.cursor].iter().map(w).sum::<usize>() + 1 > width
        {
            start += 1;
        }
        let before: String = chars[start..self.cursor].iter().collect();
        let at = chars
            .get(self.cursor)
            .map_or(" ".to_string(), |c| c.to_string());
        let used: usize = chars[start..self.cursor].iter().map(w).sum::<usize>() + 1;
        let mut after = String::new();
        let mut acc = used;
        for c in chars.iter().skip(self.cursor + 1) {
            if acc + w(c) > width {
                break;
            }
            acc += w(c);
            after.push(*c);
        }
        (before, at, after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyEvent;

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn edicao_unicode() {
        let mut t = TextInput::new("olá");
        t.handle(k(KeyCode::Char('!')));
        assert_eq!(t.value(), "olá!");
        t.handle(k(KeyCode::Left));
        t.handle(k(KeyCode::Left));
        t.handle(k(KeyCode::Backspace));
        assert_eq!(t.value(), "oá!");
        t.handle(k(KeyCode::Delete));
        assert_eq!(t.value(), "o!");
        t.handle(k(KeyCode::Home));
        t.handle(k(KeyCode::Char('日')));
        assert_eq!(t.value(), "日o!");
        t.handle(k(KeyCode::End));
        t.handle(k(KeyCode::Char('é')));
        assert_eq!(t.value(), "日o!é");
        assert!(!t.handle(k(KeyCode::Enter)) && !t.handle(k(KeyCode::Esc)));
        t.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(t.value(), "");
        t.handle(k(KeyCode::Backspace)); // sem pânico no início
        t.handle(k(KeyCode::Delete));
    }

    #[test]
    fn janela_mantem_o_cursor_visivel() {
        let t = TextInput::new("abcdefghij");
        let (b, a, r) = t.view(5);
        assert_eq!((b.as_str(), a.as_str(), r.as_str()), ("ghij", " ", ""));
        let mut t = TextInput::new("abcdefghij");
        t.handle(k(KeyCode::Home));
        let (b, a, r) = t.view(5);
        assert_eq!((b.as_str(), a.as_str(), r.as_str()), ("", "a", "bcde"));
    }
}
