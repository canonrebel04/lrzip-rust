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
        return format!("{} B", bytes);
    }
    let exp = (bytes as f64).log(UNIT as f64) as i32;
    let pre = "kMGTPE".chars().nth((exp - 1) as usize).unwrap_or('?');
    let val = bytes as f64 / (UNIT as f64).powi(exp);
    format!("{:.2} {}B", val, pre)
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
    }
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
    
    let content_width = 48;
    
    // Title styling
    let raw_title = format!(" {} Summary ", action);
    let styled_title = raw_title.clone().bold().white().on_blue().to_string();
    
    let title_visible_len = raw_title.len(); 
    let pad_total = if content_width > title_visible_len { content_width - title_visible_len } else { 0 };
    let pad_left = pad_total / 2;
    let pad_right = pad_total - pad_left;
    
    let horizontal = "─".repeat(content_width);
    
    // Top border
    println!("{}", format!("╭{}╮", horizontal).cyan());
    
    // Title row
    println!(
        "{} {}{}{} {}", 
        "│".cyan(), 
        " ".repeat(pad_left), 
        styled_title, 
        " ".repeat(pad_right), 
        "│".cyan()
    ); 
    
    // Spacer
    println!("{} {} {}", "│".cyan(), " ".repeat(content_width), "│".cyan());

    let row = |label: &str, raw_val: &str, styled_val: ColoredString| {
        let inner_width = content_width - 4; // 2 spaces left, 2 spaces right
        let label_len = label.len();
        let val_len = raw_val.len();
        let pad_len = if inner_width > (label_len + val_len) {
            inner_width - label_len - val_len
        } else {
            1
        };
        println!(
            "{}  {} {} {}  {}",
            "│".cyan(),
            label.bold().white(),
            " ".repeat(pad_len),
            styled_val,
            "│".cyan()
        );
    };

    // Labels depend on direction: compression shows original -> final;
    // decompression shows compressed (input .lrz) -> decompressed (output).
    let (first_label, second_label) = if action == "Decompression" {
        ("Compressed Size:", "Decompressed Size:")
    } else {
        ("Original Size:", "Final Size:")
    };

    // For decompression the (original, compressed) params map to
    // (decompressed output, compressed .lrz input) — display them in the
    // other order so the box reads top-down like the pipeline ran.
    let (first_raw, second_raw) = if action == "Decompression" {
        (format_size(compressed_size), format_size(original_size))
    } else {
        (format_size(original_size), format_size(compressed_size))
    };

    row(first_label, &first_raw, first_raw.cyan().bold());

    row(second_label, &second_raw, second_raw.cyan().bold());

    let ratio_raw = format!("{:.2}x", ratio);
    row("Ratio:", &ratio_raw, ratio_raw.green().bold());

    let dur_raw = format_duration(duration);
    row("Time:", &dur_raw, dur_raw.yellow());
    
    // Spacer
    println!("{} {} {}", "│".cyan(), " ".repeat(content_width), "│".cyan());
    // Bottom border
    println!("{}", format!("╰{}╯", horizontal).cyan());
}
