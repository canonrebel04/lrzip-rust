pub mod dxt;
pub mod deflate;

pub enum PreprocessKind {
    None,
    Dxt,
    Deflate,
}

pub fn preprocess(input: &[u8], dxt_enabled: bool, deflate_enabled: bool) -> (Vec<u8>, PreprocessKind) {
    if dxt_enabled {
        if let Some(transposed) = dxt::transpose(input) {
            return (transposed, PreprocessKind::Dxt);
        }
    }

    if deflate_enabled {
        if let Some(recompressed) = deflate::scan_and_decompress(input) {
            return (recompressed, PreprocessKind::Deflate);
        }
    }

    (input.to_vec(), PreprocessKind::None)
}

pub fn postprocess(input: &[u8]) -> Vec<u8> {
    if let Some(untransposed) = dxt::untranspose(input) {
        return untransposed;
    }

    if let Some(reconstructed) = deflate::reconstruct(input) {
        return reconstructed;
    }

    input.to_vec()
}
