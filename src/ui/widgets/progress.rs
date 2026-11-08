//! Barra de progresso textual: `[████░░░░] 42%  00:12`.

pub fn mmss(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// Barra com percentual conhecido.
pub fn bar(percent: f32, width: usize, elapsed_secs: u64) -> String {
    let p = percent.clamp(0.0, 100.0);
    let filled = ((p / 100.0) * width as f32).round() as usize;
    format!(
        "[{}{}] {:>3}%  {}",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled)),
        p.round() as u32,
        mmss(elapsed_secs)
    )
}

/// Indicador indeterminado (sem percentual): um bloco que vai e volta conforme o tempo.
pub fn indeterminate(width: usize, elapsed_ms: u128, elapsed_secs: u64) -> String {
    let block = (width / 5).max(2).min(width);
    let span = width.saturating_sub(block).max(1);
    let step = (elapsed_ms / 120) as usize % (span * 2);
    let pos = if step <= span { step } else { span * 2 - step };
    let mut s = String::from("[");
    for i in 0..width {
        s.push(if i >= pos && i < pos + block {
            '▒'
        } else {
            '░'
        });
    }
    format!("{s}]  ...  {}", mmss(elapsed_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barra() {
        assert_eq!(bar(50.0, 8, 12), "[████░░░░]  50%  00:12");
        assert_eq!(bar(0.0, 4, 0), "[░░░░]   0%  00:00");
        assert_eq!(bar(100.0, 4, 61), "[████] 100%  01:01");
        assert_eq!(bar(250.0, 4, 0), "[████] 100%  00:00");
        for ms in [0, 500, 5000, 99999] {
            assert_eq!(
                indeterminate(20, ms, 3)
                    .chars()
                    .filter(|c| "▒░".contains(*c))
                    .count(),
                20
            );
        }
    }
}
