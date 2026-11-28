//! duf-style table rendering for `cachette cluster status`.
//!
//! Adapted from [muesli/duf](https://github.com/muesli/duf) (MIT): ANSI themes,
//! usage bars coloured by threshold, and multi-column sorting. Rows carry their
//! sort keys alongside their display text, the way duf keeps hidden numeric
//! helper columns, so a `12.0G` cell still sorts by its raw byte count.

use std::cmp::Ordering;
use std::io::IsTerminal;

/// Colour roles from duf's themes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Color {
    Blue,
    Gray,
    Green,
    Yellow,
    Red,
}

impl Color {
    fn index(self) -> usize {
        match self {
            Self::Blue => 0,
            Self::Gray => 1,
            Self::Green => 2,
            Self::Yellow => 3,
            Self::Red => 4,
        }
    }
}

/// An ANSI theme. Every prefix is empty for the `none` theme.
#[derive(Clone, Debug)]
pub struct Theme {
    prefixes: [String; 5],
    reset: String,
}

impl Theme {
    /// * `none`/`off` — no colour.
    /// * `auto` — colour only on a terminal without `NO_COLOR`.
    /// * `dark`/`light`/`ansi` — duf's built-in palettes.
    #[must_use]
    pub fn resolve(name: &str) -> Self {
        let name = match name {
            "auto" => {
                if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
                    "none"
                } else {
                    "dark"
                }
            }
            other => other,
        };
        match name {
            "dark" => Self::from_hex("#71BEF2", "#B9BFCA", "#A8CC8C", "#DBAB79", "#E88388"),
            "light" => Self::from_hex("#000087", "#303030", "#005F00", "#FFAF00", "#D70000"),
            "ansi" => Self {
                prefixes: [
                    String::from("\x1b[94m"),
                    String::from("\x1b[37m"),
                    String::from("\x1b[92m"),
                    String::from("\x1b[93m"),
                    String::from("\x1b[91m"),
                ],
                reset: String::from("\x1b[0m"),
            },
            _ => Self::plain(),
        }
    }

    fn plain() -> Self {
        Self {
            prefixes: std::array::from_fn(|_| String::new()),
            reset: String::new(),
        }
    }

    fn from_hex(blue: &str, gray: &str, green: &str, yellow: &str, red: &str) -> Self {
        let rgb = |hex: &str| {
            let r = u8::from_str_radix(&hex[1..3], 16).unwrap_or(0);
            let g = u8::from_str_radix(&hex[3..5], 16).unwrap_or(0);
            let b = u8::from_str_radix(&hex[5..7], 16).unwrap_or(0);
            format!("\x1b[38;2;{r};{g};{b}m")
        };
        Self {
            prefixes: [rgb(blue), rgb(gray), rgb(green), rgb(yellow), rgb(red)],
            reset: String::from("\x1b[0m"),
        }
    }

    /// Paint one line; no-op when the theme has no colour.
    fn paint(&self, color: Option<Color>, text: &str) -> String {
        match color {
            Some(color) if !self.prefixes[color.index()].is_empty() => {
                format!("{}{}{}", self.prefixes[color.index()], text, self.reset)
            }
            _ => text.to_owned(),
        }
    }

    /// duf's default usage thresholds: 50% yellow, 80% red.
    #[must_use]
    pub fn usage_color(percent: f64) -> Color {
        if percent >= 80.0 {
            Color::Red
        } else if percent >= 50.0 {
            Color::Yellow
        } else {
            Color::Green
        }
    }

    /// duf's default availability thresholds: 1G red, 10G yellow.
    #[must_use]
    pub fn avail_color(bytes: u64) -> Color {
        if bytes < 1 << 30 {
            Color::Red
        } else if bytes < 10 * (1 << 30) {
            Color::Yellow
        } else {
            Color::Green
        }
    }
}

/// One sort key, mirroring duf's hidden numeric helper columns.
#[derive(Clone, Debug)]
pub enum SortKey {
    Text(String),
    Num(f64),
}

impl SortKey {
    fn compare(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Num(a), Self::Num(b)) => a.total_cmp(b),
            (Self::Text(a), Self::Text(b)) => a.cmp(b),
            (Self::Num(a), Self::Text(b)) => a.to_string().cmp(b),
            (Self::Text(a), Self::Num(b)) => a.cmp(&b.to_string()),
        }
    }
}

/// A display cell with an optional theme colour.
#[derive(Clone, Debug)]
pub struct Cell {
    text: String,
    color: Option<Color>,
}

impl Cell {
    #[must_use]
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            color: None,
        }
    }

    #[must_use]
    pub fn colored(text: impl Into<String>, color: Color) -> Self {
        Self {
            text: text.into(),
            color: Some(color),
        }
    }
}

/// A table row: display cells plus one sort key per column.
#[derive(Clone, Debug)]
pub struct Row {
    cells: Vec<Cell>,
    keys: Vec<SortKey>,
}

impl Row {
    #[must_use]
    pub fn new(cells: Vec<Cell>, keys: Vec<SortKey>) -> Self {
        Self { cells, keys }
    }
}

/// A duf-style table ready to render.
#[derive(Clone, Debug)]
pub struct Table {
    pub title: String,
    pub headers: Vec<String>,
    /// Lower-case sort names, one per column (e.g. `node`, `used`, `use%`).
    pub ids: Vec<String>,
    pub rows: Vec<Row>,
    /// Right-align flags, one per column.
    pub right: Vec<bool>,
    /// Free-form columns allowed to shrink first when the terminal is narrow.
    pub dynamic: Vec<usize>,
}

/// `--sort` options for both tables of a status render.
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub theme: String,
    /// Comma-separated keys, optional leading `-` for descending.
    pub sort: Option<String>,
}

/// duf's ASCII bar: whole `#`, a half-cell `#` for the remainder, then `.`.
#[must_use]
pub fn usage_bar(percent: f64, width: usize) -> String {
    let width = width.max(1);
    let value = percent.clamp(0.0, 100.0) / 100.0 * width as f64;
    let filled = value.floor() as usize;
    let half = value - filled as f64 >= 0.5 && filled < width;
    let empty = width.saturating_sub(filled + usize::from(half));
    format!(
        "[{}{}{}] {:>5.1}%",
        "#".repeat(filled),
        if half { "#" } else { "" },
        ".".repeat(empty),
        percent
    )
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(100)
        .max(60)
}

fn wrap_cell(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return vec![text.to_owned()];
    }
    chars
        .chunks(width)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect()
}

/// Parse `--sort node,-used` into `(column index, descending)` pairs.
fn parse_sort(spec: Option<&str>, ids: &[String]) -> Vec<(usize, bool)> {
    let Some(spec) = spec else {
        return Vec::new();
    };
    spec.split(',')
        .filter_map(|raw| {
            let raw = raw.trim();
            if raw.is_empty() {
                return None;
            }
            let (name, descending) = raw
                .strip_prefix('-')
                .map_or((raw, false), |rest| (rest, true));
            let name = name.to_ascii_lowercase();
            ids.iter()
                .position(|id| id == &name)
                .map(|index| (index, descending))
        })
        .collect()
}

/// Render one table. Empty tables are omitted, like duf.
pub fn print_table(mut table: Table, opts: &Options) {
    if table.rows.is_empty() {
        return;
    }
    let theme = Theme::resolve(&opts.theme);
    let sort = parse_sort(opts.sort.as_deref(), &table.ids);
    // Stable sort, least-significant key first, gives true multi-column order.
    for &(index, descending) in sort.iter().rev() {
        table.rows.sort_by(|a, b| {
            let order = a
                .keys
                .get(index)
                .zip(b.keys.get(index))
                .map_or(Ordering::Equal, |(left, right)| left.compare(right));
            if descending { order.reverse() } else { order }
        });
    }

    let mut widths: Vec<usize> = table
        .headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in &table.rows {
        for (index, cell) in row.cells.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(cell.text.chars().count());
            }
        }
    }
    // Every rendered line is `sum(w) + 3n + 1` chars wide: two edge chars,
    // `w + 2` per column, and a 3-char (` │ `) separator between columns.
    let line_width = |widths: &[usize]| widths.iter().sum::<usize>() + 3 * widths.len() + 1;
    let max_width = terminal_width();
    while line_width(&widths) > max_width {
        let Some(index) = table
            .dynamic
            .iter()
            .copied()
            .find(|index| widths.get(*index).is_some_and(|width| *width > 6))
        else {
            break;
        };
        widths[index] -= 1;
    }

    let border = |left: &str, mid: &str, right: &str| {
        let parts: Vec<String> = widths.iter().map(|w| "─".repeat(w + 2)).collect();
        format!("{left}{}{right}", parts.join(mid))
    };
    let render_line = |cells: &[Cell]| {
        let parts: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                let width = widths.get(index).copied().unwrap_or(0);
                let text = if table.right.get(index).copied().unwrap_or(false) {
                    format!("{:>width$}", cell.text, width = width)
                } else {
                    format!("{:<width$}", cell.text, width = width)
                };
                theme.paint(cell.color, &text)
            })
            .collect();
        format!("│ {} │", parts.join(" │ "))
    };
    let render_row = |cells: &[Cell]| {
        let wrapped: Vec<Vec<String>> = cells
            .iter()
            .enumerate()
            .map(|(index, cell)| wrap_cell(&cell.text, widths.get(index).copied().unwrap_or(1)))
            .collect();
        let lines = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        for line in 0..lines {
            let parts: Vec<Cell> = wrapped
                .iter()
                .enumerate()
                .map(|(index, cell)| Cell {
                    text: cell.get(line).cloned().unwrap_or_default(),
                    color: cells.get(index).and_then(|cell| cell.color),
                })
                .collect();
            println!("{}", render_line(&parts));
        }
    };

    println!("{}", border("╭", "┬", "╮"));
    // The title cell is wrapped by `│ ` and ` │`, four chars narrower.
    let title_width = line_width(&widths).saturating_sub(4);
    let title: String = table.title.chars().take(title_width).collect();
    println!("│ {title:<title_width$} │");
    println!("{}", border("├", "┼", "┤"));
    let headers: Vec<Cell> = table
        .headers
        .iter()
        .map(|h| Cell::plain(h.clone()))
        .collect();
    render_row(&headers);
    println!("{}", border("├", "┼", "┤"));
    for row in &table.rows {
        render_row(&row.cells);
    }
    println!("{}", border("╰", "┴", "╯"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_bar_marks_half_cells() {
        assert_eq!(usage_bar(0.0, 10), "[..........]   0.0%");
        assert_eq!(usage_bar(100.0, 10), "[##########] 100.0%");
        assert_eq!(usage_bar(25.0, 8), "[##......]  25.0%");
        assert_eq!(usage_bar(32.0, 8), "[###.....]  32.0%");
    }

    #[test]
    fn sort_spec_supports_multiple_descending_keys() {
        let ids = vec![
            String::from("node"),
            String::from("used"),
            String::from("use%"),
        ];
        assert_eq!(
            parse_sort(Some(" -USED,node "), &ids),
            vec![(1, true), (0, false)]
        );
        assert!(parse_sort(Some("bogus"), &ids).is_empty());
    }

    #[test]
    fn thresholds_match_duf_defaults() {
        assert_eq!(Theme::usage_color(10.0), Color::Green);
        assert_eq!(Theme::usage_color(50.0), Color::Yellow);
        assert_eq!(Theme::usage_color(80.0), Color::Red);
        assert_eq!(Theme::avail_color(1), Color::Red);
        assert_eq!(Theme::avail_color(1 << 30), Color::Yellow);
        assert_eq!(Theme::avail_color(10 << 30), Color::Green);
    }

    #[test]
    fn none_theme_paints_nothing() {
        let theme = Theme::resolve("none");
        assert_eq!(theme.paint(Some(Color::Red), "x"), "x");
        assert!(
            Theme::resolve("ansi")
                .paint(Some(Color::Red), "x")
                .contains("\x1b[")
        );
    }
}
