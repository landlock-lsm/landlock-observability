// SPDX-License-Identifier: MIT OR Apache-2.0

use ratatui::style::{Color, Modifier, Style};

pub(super) const fn normal() -> Style {
    Style::new()
}

pub(super) const fn heading() -> Style {
    Style::new()
        .fg(Color::LightCyan)
        .add_modifier(Modifier::BOLD)
}

pub(super) const fn selected() -> Style {
    Style::new().bg(Color::Indexed(238))
}

pub(super) const fn related() -> Style {
    Style::new().bg(Color::Indexed(236))
}

pub(super) const fn observed() -> Style {
    Style::new().fg(Color::LightGreen)
}

pub(super) const fn tombstone() -> Style {
    Style::new().fg(Color::DarkGray).add_modifier(Modifier::DIM)
}

pub(super) const fn unknown() -> Style {
    Style::new()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::ITALIC)
}

pub(super) const fn trace_only() -> Style {
    Style::new().fg(Color::LightMagenta)
}

pub(super) const fn hot() -> Style {
    Style::new()
        .fg(Color::LightRed)
        .add_modifier(Modifier::BOLD)
}

pub(super) const fn recent() -> Style {
    Style::new().fg(Color::LightRed)
}

pub(super) const fn cooling() -> Style {
    Style::new().fg(Color::Gray)
}

pub(super) const fn cold() -> Style {
    Style::new().fg(Color::DarkGray)
}

pub(super) fn recency(age_ns: u64) -> Style {
    match age_ns {
        0..1_000_000_000 => hot(),
        1_000_000_000..5_000_000_000 => recent(),
        5_000_000_000..30_000_000_000 => cooling(),
        _ => cold(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recency_bands_have_exact_boundaries() {
        assert_eq!(recency(999_999_999), hot());
        assert_eq!(recency(1_000_000_000), recent());
        assert_eq!(recency(5_000_000_000), cooling());
        assert_eq!(recency(30_000_000_000), cold());
    }

    #[test]
    fn tombstone_is_distinct_from_cold_and_unknown() {
        assert!(tombstone().add_modifier.contains(Modifier::DIM));
        assert_ne!(tombstone(), cold());
        assert_ne!(tombstone(), unknown());
    }
}
