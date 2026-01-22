use std::ops::Range;

pub const MINIMUM_MATCH: usize = 31;
pub const GREAT_MATCH: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSpec {
    pub size: u64,
    pub slide_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpec {
    pub index: u64,
    pub offset: u64,
    pub size: u64,
    pub window: WindowSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPlan {
    pub chunk_bytes: u8,
    pub chunk_count: u64,
    pub max_chunk: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMap {
    pub total_size: u64,
    pub chunks: Vec<ChunkSpec>,
    pub plan: ChunkPlan,
}

impl ChunkMap {
    pub fn range_for(&self, index: u64) -> Option<Range<u64>> {
        self.chunks.get(index as usize).map(|chunk| {
            let start = chunk.offset;
            let end = chunk.offset.saturating_add(chunk.size);
            start..end
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RzipConfig {
    pub max_chunk: u64,
    pub max_mmap: u64,
    pub window: u64,
    pub page_size: u64,
    pub level: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RzipState {
    pub chunk_index: u64,
    pub chunk_bytes: u8,
    pub chunk_size: u64,
    pub window: WindowSpec,
}

pub fn plan_chunks(total_size: u64, config: RzipConfig) -> ChunkPlan {
    let mut chunk_bytes = 1u8;
    let mut bits = 8u64;
    while total_size >> bits > 0 {
        bits += 8;
    }
    if bits > 0 {
        chunk_bytes = (bits / 8) as u8;
        if bits % 8 != 0 {
            chunk_bytes = chunk_bytes.saturating_add(1);
        }
    }

    let max_chunk = config.max_chunk.max(1);
    let chunk_count = (total_size + max_chunk - 1) / max_chunk;

    ChunkPlan {
        chunk_bytes,
        chunk_count,
        max_chunk,
    }
}

pub fn build_chunk_map(total_size: u64, config: RzipConfig) -> ChunkMap {
    let plan = plan_chunks(total_size, config);
    let mut chunks = Vec::with_capacity(plan.chunk_count as usize);

    let mut offset = 0u64;
    for index in 0..plan.chunk_count {
        let remaining = total_size.saturating_sub(offset);
        let size = remaining.min(plan.max_chunk);
        let window = WindowSpec {
            size: config.window,
            slide_size: config.max_mmap.min(config.window),
        };
        chunks.push(ChunkSpec {
            index,
            offset,
            size,
            window,
        });
        offset = offset.saturating_add(size);
    }

    ChunkMap {
        total_size,
        chunks,
        plan,
    }
}

pub type Tag = u64;

#[derive(Debug, Clone, Copy, Default)]
struct HashEntry {
    offset: u64,
    tag: Tag,
}

impl HashEntry {
    #[inline]
    fn is_empty(&self) -> bool {
        self.offset == 0 && self.tag == 0
    }
}

struct Level {
    mb_used: usize,
    initial_freq: u32,
    _max_chain_len: usize,
}

const LEVELS: [Level; 10] = [
    Level { mb_used: 1, initial_freq: 4, _max_chain_len: 1 },
    Level { mb_used: 2, initial_freq: 4, _max_chain_len: 2 },
    Level { mb_used: 4, initial_freq: 4, _max_chain_len: 2 },
    Level { mb_used: 8, initial_freq: 4, _max_chain_len: 2 },
    Level { mb_used: 16, initial_freq: 4, _max_chain_len: 3 },
    Level { mb_used: 32, initial_freq: 4, _max_chain_len: 4 },
    Level { mb_used: 32, initial_freq: 2, _max_chain_len: 6 },
    Level { mb_used: 64, initial_freq: 1, _max_chain_len: 16 },
    Level { mb_used: 64, initial_freq: 1, _max_chain_len: 32 },
    Level { mb_used: 64, initial_freq: 1, _max_chain_len: 128 },
];

pub struct RollingHash {
    table: [Tag; 256],
}

impl RollingHash {
    pub fn new() -> Self {
        let mut table = [0u64; 256];
        // Use a fixed seed for reproducibility, similar to lrzip-next's intention if not implementation.
        // These are just some "random" 64-bit values.
        for i in 0..256 {
            table[i] = (i as u64).wrapping_mul(0x9E3779B97F4A7C15) ^ 0xBF58476D1CE4E5B9;
        }
        Self { table }
    }

    #[inline]
    pub fn full_tag(&self, data: &[u8]) -> Tag {
        let mut tag = 0;
        for &b in data.iter().take(MINIMUM_MATCH) {
            tag ^= self.table[b as usize];
        }
        tag
    }

    #[inline]
    pub fn roll(&self, tag: Tag, old_byte: u8, new_byte: u8) -> Tag {
        tag ^ self.table[old_byte as usize] ^ self.table[new_byte as usize]
    }

    #[inline]
    pub fn roll_4(&self, start_tag: Tag, old: &[u8; 4], new: &[u8; 4]) -> [Tag; 4] {
        // Scalar unrolling to hide load latency
        let t_old0 = self.table[old[0] as usize];
        let t_new0 = self.table[new[0] as usize];
        let t_old1 = self.table[old[1] as usize];
        let t_new1 = self.table[new[1] as usize];
        let t_old2 = self.table[old[2] as usize];
        let t_new2 = self.table[new[2] as usize];
        let t_old3 = self.table[old[3] as usize];
        let t_new3 = self.table[new[3] as usize];

        let val0 = t_old0 ^ t_new0;
        let val1 = t_old1 ^ t_new1;
        let val2 = t_old2 ^ t_new2;
        let val3 = t_old3 ^ t_new3;

        let tag0 = start_tag ^ val0;
        let tag1 = tag0 ^ val1;
        let tag2 = tag1 ^ val2;
        let tag3 = tag2 ^ val3;

        [tag0, tag1, tag2, tag3]
    }
}

impl Default for RollingHash {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HashTable {
    entries: Vec<HashEntry>,
    hash_bits: u32,
    hash_limit: usize,
    hash_count: usize,
    minimum_tag_mask: Tag,
    tag_clean_ptr: usize,
}

impl HashTable {
    pub fn new(level_idx: u8) -> Self {
        let level = &LEVELS[level_idx.min(9) as usize];
        let hash_size_bytes = level.mb_used * 1024 * 1024;
        let mut hash_bits = 0;
        while (1 << hash_bits) * std::mem::size_of::<HashEntry>() < hash_size_bytes {
            hash_bits += 1;
        }

        let size = 1 << hash_bits;
        let entries = vec![HashEntry::default(); size];
        let hash_limit = size / 3 * 2; // 66% full

        Self {
            entries,
            hash_bits,
            hash_limit,
            hash_count: 0,
            minimum_tag_mask: (1 << level.initial_freq) - 1,
            tag_clean_ptr: 0,
        }
    }

    pub fn clear(&mut self, level_idx: u8) {
        let level = &LEVELS[level_idx.min(9) as usize];
        // We assume hash_bits and size stay same for the same level.
        // If it changes, we'd need to reallocate, but usually level is constant.
        for entry in &mut self.entries {
            entry.tag = 0;
            entry.offset = 0;
        }
        self.hash_count = 0;
        self.minimum_tag_mask = (1 << level.initial_freq) - 1;
        self.tag_clean_ptr = 0;
    }

    #[inline]
    fn primary_hash(&self, tag: Tag) -> usize {
        (tag as usize) & ((1 << self.hash_bits) - 1)
    }

    pub fn insert(&mut self, mut tag: Tag, mut offset: u64) {
        let mask = (1 << self.hash_bits) - 1;
        let mut h = (tag as usize) & mask;
        let better_than_min = (self.minimum_tag_mask << 1) | 1;

        loop {
            let entry = &mut self.entries[h];
            
            if entry.tag == 0 {
                entry.tag = tag;
                entry.offset = offset;
                self.hash_count += 1;
                return;
            }

            if (entry.tag & better_than_min) != better_than_min {
                entry.tag = tag;
                entry.offset = offset;
                return;
            }

            if entry.tag.trailing_ones() < tag.trailing_ones() {
                std::mem::swap(&mut entry.tag, &mut tag);
                std::mem::swap(&mut entry.offset, &mut offset);
                // Continue with the swapped out tag
            } else if entry.tag == tag {
                // To avoid long chains of identical tags, we just replace the existing one
                // with the newer offset (which is usually better for rzip matches).
                entry.offset = offset;
                return;
            }

            h = (h + 1) & mask;
        }
    }

    pub fn maybe_clean(&mut self) {
        if self.hash_count > self.hash_limit {
            self.clean_one();
        }
    }

    fn clean_one(&mut self) {
        let better_than_min = (self.minimum_tag_mask << 1) | 1;
        let mask = (1 << self.hash_bits) - 1;

        loop {
            for _ in 0..1024 { // Clean in batches to avoid spending too much time here
                let h = self.tag_clean_ptr;
                let entry = &mut self.entries[h];
                if !entry.is_empty() && (entry.tag & better_than_min) != better_than_min {
                    entry.tag = 0;
                    entry.offset = 0;
                    self.hash_count -= 1;
                    return;
                }
                self.tag_clean_ptr = (self.tag_clean_ptr + 1) & mask;
                if self.tag_clean_ptr == 0 {
                    self.minimum_tag_mask = better_than_min;
                    // Restart search with new mask
                    return;
                }
            }
            // If we didn't find anything in 1024 entries, keep going or return if we've seen everything
            if self.tag_clean_ptr == 0 {
                return;
            }
        }
    }

    pub fn find_best_match(&self, tag: Tag, data: &[u8], p: usize, end: usize, last_match: usize) -> Option<(u64, usize, usize)> {
        let mut best_len = 0;
        let mut best_offset = 0;
        let mut best_reverse = 0;

        let mut h = self.primary_hash(tag);
        let mask = (1 << self.hash_bits) - 1;

        loop {
            let entry = &self.entries[h];
            if entry.is_empty() {
                break;
            }

            if entry.tag == tag {
                let op = entry.offset as usize;
                if op < p {
                    if let Some((len, rev)) = self.match_len(data, p, op, end, last_match) {
                        if len > best_len {
                            best_len = len;
                            best_offset = entry.offset - rev as u64;
                            best_reverse = rev;
                        }
                    }
                }
            }

            h = (h + 1) & mask;
            // Limit search depth? lrzip-next doesn't seem to explicitly, but the thinning helps.
            // In lrzip-next it stops when it finds an empty bucket.
        }

        if best_len >= MINIMUM_MATCH {
            Some((best_offset, best_len, best_reverse))
        } else {
            None
        }
    }

    fn match_len(&self, data: &[u8], p0: usize, op0: usize, end: usize, last_match: usize) -> Option<(usize, usize)> {
        if op0 >= p0 {
            return None;
        }

        let mut p = p0;
        let mut op = op0;

        while p < end && data[p] == data[op] {
            p += 1;
            op += 1;
        }

        let mut len = p - p0;
        
        // Match backwards
        p = p0;
        op = op0;
        let back_limit = last_match;
        while p > back_limit && op > 0 && data[p - 1] == data[op - 1] {
            p -= 1;
            op -= 1;
        }
        
        let rev = p0 - p;
        len += rev;

        if len >= MINIMUM_MATCH {
            Some((len, rev))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RzipControl {
    Literal { len: u32 },
    Match { len: u32, offset: u64 },
}

pub struct RzipStats {
    pub inserts: u64,
    pub literals: u64,
    pub literal_bytes: u64,
    pub matches: u64,
    pub match_bytes: u64,
    pub tag_hits: u64,
    pub tag_misses: u64,
}

pub fn compress_chunk(
    data: &[u8],
    level: u8,
    hasher: &RollingHash,
    table: &mut HashTable,
    mut control_cb: impl FnMut(RzipControl),
) -> RzipStats {
    let mut stats = RzipStats {
        inserts: 0,
        literals: 0,
        literal_bytes: 0,
        matches: 0,
        match_bytes: 0,
        tag_hits: 0,
        tag_misses: 0,
    };

    table.clear(level);
    let mut p = 0;
    let end = data.len().saturating_sub(MINIMUM_MATCH);
    let mut last_match = 0;

    let mut current_best: Option<(u64, usize, usize)> = None;
    let mut current_best_p = 0;

    let mut tag = if end > 0 {
        hasher.full_tag(data)
    } else {
        0
    };

    let tag_mask = (1 << LEVELS[level.min(9) as usize].initial_freq) - 1;

    'outer: while p < end {
        // Optimistically process 4 bytes at a time if possible
        if p + 4 < end && p + 4 + MINIMUM_MATCH < data.len() {
             let old = [data[p], data[p+1], data[p+2], data[p+3]];
             let new_idx = p + MINIMUM_MATCH;
             let new = [data[new_idx], data[new_idx+1], data[new_idx+2], data[new_idx+3]];
             
             let next_tags = hasher.roll_4(tag, &old, &new);
             let tags_to_check = [tag, next_tags[0], next_tags[1], next_tags[2]];
             
             // We need to iterate 4 times
             for (k, &t) in tags_to_check.iter().enumerate() {
                 let current_pos = p + k; // This is the 'p' at start of original loop body
                 
                 // p is implicitly current_pos for data access
                 // But original code did p += 1 before match check.
                 // So "p" for match check is current_pos + 1.
                 let match_check_p = current_pos + 1;
                 
                  // Don't look for match if tag doesn't meet minimum requirements
                if (t & table.minimum_tag_mask) == table.minimum_tag_mask {
                    if let Some((offset, len, rev)) = table.find_best_match(t, data, match_check_p - 1, end + MINIMUM_MATCH, last_match) {
                        stats.tag_hits += 1;
                        let actual_p = match_check_p - 1 - rev;
                        
                        let is_better = match current_best {
                            None => true,
                            Some((_, best_len, _)) => {
                                len > best_len || (len == best_len && actual_p < current_best_p)
                            }
                        };

                        if is_better {
                            current_best = Some((offset, len, rev));
                            current_best_p = actual_p;
                        }
                    } else {
                        stats.tag_misses += 1;
                    }
                }

                // Periodically insert into hash table
                if (t & tag_mask) == tag_mask {
                    stats.inserts += 1;
                    table.insert(t, (match_check_p - 1) as u64);
                    table.maybe_clean();
                }

                // Check if we should emit a match
                if let Some((offset, len, _rev)) = current_best {
                    if len >= GREAT_MATCH || match_check_p >= current_best_p + MINIMUM_MATCH {
                        // Emit literal up to match start
                        if last_match < current_best_p {
                            let lit_len = (current_best_p - last_match) as u32;
                            control_cb(RzipControl::Literal { len: lit_len });
                            stats.literals += 1;
                            stats.literal_bytes += lit_len as u64;
                        }

                        // Emit match
                        control_cb(RzipControl::Match { len: len as u32, offset });
                        stats.matches += 1;
                        stats.match_bytes += len as u64;

                        last_match = current_best_p + len;
                        p = last_match; // Update p global
                        current_best = None;

                        // Reset tag for new position
                        if p < end {
                            tag = hasher.full_tag(&data[p..]);
                        }
                        
                        // Break inner loop, continue outer with new p
                        continue 'outer;
                    }
                }
             }
             
             // If we completed the loop without emitting, update p and tag
             p += 4;
             tag = next_tags[3];
             continue;
        }

        // Fallback for single step (end of buffer or special cases)
        let t = tag;
        
        // Rolling hash for next iteration
        if p + 1 < end + MINIMUM_MATCH {
            tag = hasher.roll(tag, data[p], data[p + MINIMUM_MATCH]);
        }
        p += 1;

        // Don't look for match if tag doesn't meet minimum requirements
        if (t & table.minimum_tag_mask) == table.minimum_tag_mask {
            if let Some((offset, len, rev)) = table.find_best_match(t, data, p - 1, end + MINIMUM_MATCH, last_match) {
                stats.tag_hits += 1;
                let actual_p = p - 1 - rev;
                
                let is_better = match current_best {
                    None => true,
                    Some((_, best_len, _)) => {
                        len > best_len || (len == best_len && actual_p < current_best_p)
                    }
                };

                if is_better {
                    current_best = Some((offset, len, rev));
                    current_best_p = actual_p;
                }
            } else {
                stats.tag_misses += 1;
            }
        }

        // Periodically insert into hash table
        if (t & tag_mask) == tag_mask {
            stats.inserts += 1;
            table.insert(t, (p - 1) as u64);
            table.maybe_clean();
        }

        // Check if we should emit a match
        if let Some((offset, len, _rev)) = current_best {
            if len >= GREAT_MATCH || p >= current_best_p + MINIMUM_MATCH {
                // Emit literal up to match start
                if last_match < current_best_p {
                    let lit_len = (current_best_p - last_match) as u32;
                    control_cb(RzipControl::Literal { len: lit_len });
                    stats.literals += 1;
                    stats.literal_bytes += lit_len as u64;
                }

                // Emit match
                control_cb(RzipControl::Match { len: len as u32, offset });
                stats.matches += 1;
                stats.match_bytes += len as u64;

                last_match = current_best_p + len;
                p = last_match;
                current_best = None;

                // Reset tag for new position
                if p < end {
                    tag = hasher.full_tag(&data[p..]);
                }
            }
        }
    }

    // Pending match
    if let Some((offset, len, _rev)) = current_best {
        // Emit literal up to match start
        if last_match < current_best_p {
            let lit_len = (current_best_p - last_match) as u32;
            control_cb(RzipControl::Literal { len: lit_len });
            stats.literals += 1;
            stats.literal_bytes += lit_len as u64;
        }

        // Emit match
        control_cb(RzipControl::Match { len: len as u32, offset });
        stats.matches += 1;
        stats.match_bytes += len as u64;

        last_match = current_best_p + len;
    }

    // Final literal
    if last_match < data.len() {
        let lit_len = (data.len() - last_match) as u32;
        control_cb(RzipControl::Literal { len: lit_len });
        stats.literals += 1;
        stats.literal_bytes += lit_len as u64;
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_hash() {
        let hasher = RollingHash::new();
        let data = b"This is a test of the rolling hash function.";
        let tag0 = hasher.full_tag(&data[0..31]);
        let tag1 = hasher.full_tag(&data[1..32]);
        let rolled = hasher.roll(tag0, data[0], data[31]);
        assert_eq!(tag1, rolled);
    }

    #[test]
    fn test_rzip_repeating() {
        let mut data = vec![0u8; 1000];
        // Create a pattern
        for i in 0..100 {
            data[i] = i as u8;
            data[i + 200] = i as u8;
            data[i + 400] = i as u8;
        }
        
        let mut controls = Vec::new();
        let hasher = RollingHash::new();
        let mut table = HashTable::new(7);
        let stats = compress_chunk(&data, 7, &hasher, &mut table, |ctrl| {
            controls.push(ctrl);
        });
        
        println!("Stats: {:?}", stats);
        for ctrl in &controls {
            println!("Control: {:?}", ctrl);
        }
        
        assert!(stats.matches >= 2);
        assert!(stats.match_bytes >= 200);
    }

    impl std::fmt::Debug for RzipStats {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RzipStats")
                .field("inserts", &self.inserts)
                .field("literals", &self.literals)
                .field("literal_bytes", &self.literal_bytes)
                .field("matches", &self.matches)
                .field("match_bytes", &self.match_bytes)
                .field("tag_hits", &self.tag_hits)
                .field("tag_misses", &self.tag_misses)
                .finish()
        }
    }
}
