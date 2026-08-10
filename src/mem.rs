//! Memory-aware defaults: automatically cap chunk-compression concurrency
//! (and shrink zpaq block size when needed) so default runs don't OOM on
//! big archives. The zpaq backend is the memory driver — each ~100MB chunk
//! holds copies of the streams plus the LZ77 suffix-array sort and model
//! tables (~10x the chunk size at L2/L3), so -t16 can exceed RAM on modest
//! machines (user hit "libzpaq error: Out of memory" on a 58GB archive at
//! 78% — 16 concurrent compressors). The budget is a HARD limit derived
//! from the machine's TOTAL physical RAM (50%), so the program's footprint
//! is bounded regardless of what else runs. LRZIP_MEM_LIMIT=<bytes>
//! overrides the machine RAM used for the limit (testing / power users).

/// Bytes of physical RAM on this machine (the "max system ram" the hard
/// limit scales with), or 0 if undetectable (callers treat 0 as "unknown,
/// don't clamp").
pub fn total_memory_bytes() -> u64 {
    if let Ok(s) = std::env::var("LRZIP_MEM_LIMIT") {
        if let Ok(v) = s.trim().parse::<u64>() {
            return v;
        }
    }
    imp::total()
}

/// Conservative per-chunk peak-memory estimate for the zpaq backend:
/// stream copies + output buffer + divsufsort suffix array (L2/L3/L4/L5) +
/// LZ77 hash table + model tables. Deliberately an over-estimate with a
/// fixed base so tiny chunks don't under-estimate.
const BASE: u64 = 192 * 1024 * 1024;

pub fn estimate_chunk_peak(chunk_bytes: u64, level: u8) -> u64 {
    // L1 uses a hash table only (no suffix array); L2+ sorts (SA ~5-8x input)
    // and adds LZ77 tables + larger models. 10x is the safe bound.
    let factor = if level <= 1 { 2.0 } else { 10.0 };
    BASE + (chunk_bytes as f64 * factor) as u64
}

/// Memory-safe concurrency for compressing `chunk_bytes` chunks at `level`:
/// (threads to use, optional auto zpaq block size in MiB when even one
/// thread is tight). `requested` is the user's -t (or the core count);
/// `total_ram` is total_memory_bytes() — the HARD budget is 50% of it, so
/// the program can never claim more than half the machine's RAM.
pub fn memory_safe_threads(requested: usize, chunk_bytes: u64, level: u8, total_ram: u64) -> (usize, Option<u32>) {
    if total_ram == 0 || requested <= 1 {
        return (requested, None);
    }
    // Hard limit: half of physical RAM goes to the zpaq stage, maximum.
    let budget = total_ram / 2;
    let per_chunk = estimate_chunk_peak(chunk_bytes, level);
    let fit = budget / per_chunk;
    if fit >= requested as u64 {
        return (requested, None);
    }
    if fit >= 1 {
        return (fit as usize, None);
    }
    // Even one thread doesn't fit: shrink the zpaq block size so each
    // block's model/SA fits the budget (min 8 MiB).
    let target_mb = ((budget - BASE) / 8 / (1024 * 1024)).max(8) as u32;
    (1, Some(target_mb))
}

#[cfg(windows)]
mod imp {
    use std::mem::MaybeUninit;

    #[repr(C)]
    struct MEMORYSTATUSEX {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(lp_buffer: *mut MEMORYSTATUSEX) -> i32;
    }

    pub fn total() -> u64 {
        unsafe {
            let mut st = MaybeUninit::<MEMORYSTATUSEX>::uninit();
            let p = st.as_mut_ptr();
            (*p).dw_length = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(p) != 0 {
                (*p).ull_total_phys
            } else {
                0
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    fn meminfo_value(key: &str) -> u64 {
        // Linux: MemTotal/MemAvailable from /proc/meminfo (kB).
        let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
            return 0;
        };
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix(key) {
                if let Ok(kb) = rest.trim().trim_end_matches("kB").trim().parse::<u64>() {
                    return kb * 1024;
                }
            }
        }
        0
    }

    pub fn total() -> u64 {
        meminfo_value("MemTotal:")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_scales_with_level() {
        let chunk = 100 * 1024 * 1024;
        let l1 = estimate_chunk_peak(chunk, 1);
        let l3 = estimate_chunk_peak(chunk, 3);
        assert!(l1 < l3, "L1 must estimate lighter than L3");
        assert!(l3 > chunk, "L3 must exceed the chunk size (SA + models)");
        assert_eq!(estimate_chunk_peak(chunk, 3), estimate_chunk_peak(chunk, 5));
    }

    #[test]
    fn test_no_clamp_with_unknown_memory() {
        assert_eq!(memory_safe_threads(16, 100 * 1024 * 1024, 3, 0), (16, None));
        assert_eq!(memory_safe_threads(1, 100 * 1024 * 1024, 3, 1 << 30), (1, None));
    }

    #[test]
    fn test_clamps_when_tight() {
        // 8 GiB total RAM -> hard budget 4 GiB; 100MB chunks at L3
        // (~1.2 GiB est each): 16 threads clamp to ~3.
        let (t, z) = memory_safe_threads(16, 100 * 1024 * 1024, 3, 8 << 30);
        assert!(t >= 2 && t < 16, "expected a clamp in [2,16), got {}", t);
        assert_eq!(z, None);
    }

    #[test]
    fn test_hard_limit_scales_with_total_ram() {
        // Same request, double the RAM -> at least twice the concurrency.
        let (t16, _) = memory_safe_threads(16, 100 * 1024 * 1024, 3, 16 << 30);
        let (t8, _) = memory_safe_threads(16, 100 * 1024 * 1024, 3, 8 << 30);
        assert!(t16 >= t8, "more RAM must not reduce concurrency ({} vs {})", t16, t8);
        // 64 GiB -> budget 32 GiB -> 16 threads fit unclamped.
        let (t64, z64) = memory_safe_threads(16, 100 * 1024 * 1024, 3, 64 << 30);
        assert_eq!(t64, 16);
        assert_eq!(z64, None);
    }

    #[test]
    fn test_auto_zpaqbs_when_one_thread_doesnt_fit() {
        // 1 GiB total, 1 GiB chunks at L3: even 1 thread is too big.
        let (t, z) = memory_safe_threads(16, 1024 * 1024 * 1024, 3, 1 << 30);
        assert_eq!(t, 1);
        assert!(z.is_some(), "expected an auto zpaq block size");
        let mb = z.unwrap();
        assert!(mb >= 8 && mb < 1024, "auto block size implausible: {} MiB", mb);
    }

    #[test]
    fn test_no_clamp_on_roomy_machine() {
        // 64 GiB total, 100MB chunks at L3: 16 threads fit fine.
        let (t, z) = memory_safe_threads(16, 100 * 1024 * 1024, 3, 64 << 30);
        assert_eq!(t, 16);
        assert_eq!(z, None);
    }
}
