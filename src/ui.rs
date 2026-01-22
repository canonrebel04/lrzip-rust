use std::time::Duration;
use colored::*;

pub fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    let (num_str, suffix) = s.find(|c: char| !c.is_digit(10))
        .map(|i| s.split_at(i))
        .unwrap_or((s, ""));

    let num: usize = num_str.parse().ok()?;
    let mult: usize = match suffix.to_lowercase().as_str() {
        "" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return None,
    };
    Some(num * mult)
}

pub fn format_size(bytes: u64) -> String {
    const UNIT: u64 = 1000;
    if bytes < UNIT {
        return format!("{} B", bytes).cyan().to_string();
    }
    let exp = (bytes as f64).log(UNIT as f64) as i32;
    let pre = "kMGTPE".chars().nth((exp - 1) as usize).unwrap_or('?');
    let val = bytes as f64 / (UNIT as f64).powi(exp);
    format!("{:.2} {}B", val, pre).cyan().bold().to_string()
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.2}s", secs)
    } else {
        let min = (secs / 60.0).floor();
        let s = secs % 60.0;
        format!("{:.0}m {:.0}s", min, s)
    }.yellow().to_string()
}

pub fn print_summary(
    original_size: u64,
    compressed_size: u64,
    duration: Duration,
    action: &str, // "Compression" or "Decompression"
) {
    let ratio = if compressed_size > 0 {
        original_size as f64 / compressed_size as f64
    } else {
        0.0
    };
    
    let box_width = 50;
    // content width inside │...│ is box_width - 2
    let content_width = box_width - 2;
    
    // Title styling
    let raw_title = format!(" {} Summary ", action);
    let styled_title = raw_title.clone().bold().white().on_blue().to_string();
    
    // Calculate padding manually because ANSI codes mess up format!'s width props
    let title_visible_len = raw_title.len(); 
    let pad_total = if content_width > title_visible_len { content_width - title_visible_len } else { 0 };
    let pad_left = pad_total / 2;
    let pad_right = pad_total - pad_left;
    
    let horizontal = "─".repeat(content_width);
    
    // Top border
    println!("{}", format!("╭{}╮", horizontal).blue());
    
    // Title row
    println!(
        "{} {}{}{} {}", 
        "│".blue(), 
        " ".repeat(pad_left), 
        styled_title, 
        " ".repeat(pad_right), 
        "│".blue()
    ); 
    
    // Spacer
    println!("{} {:width$} {}", "│".blue(), "", "│".blue(), width = content_width);

    let row = |label: &str, value: String| {
        // Label col: 15 chars, Value col: 31 chars. Total 46. Spaces: 1 before, 1 between, 1 after?
        // Let's do: "  Label:       Value  "
        // Fixed layout: " {:<15} {:>31} " is 48 chars. Perfect.
        println!("{} {:<15} {:>31} {}", "│".blue(), label.bold().white(), value, "│".blue());
    };

    row("Original Size:", format_size(original_size));
    row("Final Size:", format_size(compressed_size));
    row("Ratio:", format!("{:.2}x", ratio).green().bold().to_string());
    row("Time:", format_duration(duration));
    
    // Spacer
    println!("{} {:width$} {}", "│".blue(), "", "│".blue(), width = content_width);
    // Bottom border
    println!("{}", format!("╰{}╯", horizontal).blue());
}
