//! Cálculo de rolagem para listas com seleção.

/// Novo deslocamento para que `selected` fique visível em `height` linhas.
pub fn scroll_offset(offset: usize, selected: usize, height: usize, len: usize) -> usize {
    if height == 0 || len <= height {
        return 0;
    }
    let mut off = offset.min(len - height);
    if selected < off {
        off = selected;
    } else if selected >= off + height {
        off = selected + 1 - height;
    }
    off
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolagem() {
        assert_eq!(scroll_offset(0, 0, 5, 3), 0);
        assert_eq!(scroll_offset(0, 7, 5, 20), 3);
        assert_eq!(scroll_offset(3, 4, 5, 20), 3);
        assert_eq!(scroll_offset(10, 2, 5, 20), 2);
        assert_eq!(scroll_offset(99, 19, 5, 20), 15);
        assert_eq!(scroll_offset(0, 0, 0, 20), 0);
    }
}
