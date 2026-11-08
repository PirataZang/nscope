//! Utilitários: sanitização de texto externo, quebra de linha, OSC 52 e detecção de privilégios.

use std::process::{Command, Stdio};

/// Caracteres que mudam a direção do texto ou têm largura zero (usados para enganar o olho).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}'
        | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E007F}')
}

fn clean_char(c: char) -> char {
    match c {
        '\t' => ' ',
        c if c.is_control() || is_invisible(c) => '·',
        c => c,
    }
}

/// Texto de uma linha só, seguro para desenhar: controles (inclusive ESC e C1) e quebras viram `·`,
/// tab vira espaço, bidi e largura zero são neutralizados. Texto de um host remoto nunca injeta escapes.
pub fn clean(s: &str) -> String {
    s.chars().map(clean_char).collect()
}

/// Igual a [`clean`], mas preserva quebras de linha (`\n`); `\r` é descartado.
pub fn clean_multiline(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '\r')
        .map(|c| if c == '\n' { c } else { clean_char(c) })
        .collect()
}

/// Quebra `s` em linhas de no máximo `width` colunas (por palavras; palavras longas são cortadas).
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    use unicode_width::UnicodeWidthChar;
    let width = width.max(1);
    let mut out = Vec::new();
    for para in s.split('\n') {
        let mut line = String::new();
        let mut w = 0usize;
        for word in para.split(' ') {
            let ww: usize = word.chars().map(|c| c.width().unwrap_or(0)).sum();
            if w > 0 && w + 1 + ww <= width {
                line.push(' ');
                line.push_str(word);
                w += 1 + ww;
                continue;
            }
            if w > 0 {
                out.push(std::mem::take(&mut line));
                w = 0;
            }
            if ww <= width {
                line.push_str(word);
                w = ww;
            } else {
                for ch in word.chars() {
                    let cw = ch.width().unwrap_or(0);
                    if w + cw > width {
                        out.push(std::mem::take(&mut line));
                        w = 0;
                    }
                    line.push(ch);
                    w += cw;
                }
            }
        }
        out.push(line);
    }
    out
}

/// Corta `s` para caber em `width` colunas, acrescentando `…` se cortou.
pub fn truncate(s: &str, width: usize) -> String {
    use unicode_width::UnicodeWidthChar;
    let total: usize = s.chars().map(|c| c.width().unwrap_or(0)).sum();
    if total <= width {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = c.width().unwrap_or(0);
        if w + cw + 1 > width {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for ch in data.chunks(3) {
        let n = (u32::from(ch[0]) << 16)
            | (u32::from(*ch.get(1).unwrap_or(&0)) << 8)
            | u32::from(*ch.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= ch.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Sequência OSC 52 que pede ao terminal para copiar `text` para a área de transferência.
pub fn osc52(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", base64(text.as_bytes()))
}

/// O processo atual tem privilégios de administrador? (UID 0 em Unix; `net session` no Windows.)
/// Usa programas do sistema em vez de `unsafe`/libc. Em caso de dúvida, responde "não".
pub fn is_privileged() -> bool {
    let run = |prog: &str, args: &[&str]| {
        Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
    };
    if cfg!(windows) {
        run("net", &["session"]).is_some_and(|o| o.status.success())
    } else {
        run("id", &["-u"]).is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitiza_escapes_e_controles() {
        let evil = "a\x1b[2Jb\x1b]0;titulo\x07c\x7fd\u{9b}31me\u{0}f\tg\rh\ni";
        let s = clean(evil);
        assert!(!s.chars().any(|c| c.is_control()), "{s:?}");
        assert_eq!(clean("a\tb"), "a b");
        assert_eq!(clean("x\x1by"), "x·y");
    }

    #[test]
    fn neutraliza_bidi_e_largura_zero() {
        for c in [
            '\u{202E}', '\u{202D}', '\u{2066}', '\u{2069}', '\u{200B}', '\u{200F}', '\u{FEFF}',
            '\u{2060}', '\u{061C}',
        ] {
            assert_eq!(clean(&format!("a{c}b")), "a·b", "{c:?}");
        }
        assert_eq!(clean("olá, mundo — ✓ 日本"), "olá, mundo — ✓ 日本");
    }

    #[test]
    fn multiline_preserva_quebras() {
        assert_eq!(clean_multiline("a\r\nb\x1b[0m\tc"), "a\nb·[0m c");
    }

    #[test]
    fn quebra_de_linha() {
        assert_eq!(
            wrap("um dois tres quatro", 9),
            ["um dois", "tres", "quatro"]
        );
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("a\n\nb", 5), ["a", "", "b"]);
        assert!(wrap("", 5) == [""]);
    }

    #[test]
    fn corta_com_reticencias() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }

    #[test]
    fn base64_e_osc52() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(osc52("nmap"), "\x1b]52;c;bm1hcA==\x07");
    }
}
