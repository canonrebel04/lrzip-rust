use std::ops::Range;

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
