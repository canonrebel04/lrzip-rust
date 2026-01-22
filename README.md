# lrzip-rust

A high-performance, safe Rust rewrite of the `lrzip` compression utility, designed for maximum compatibility and modern user experience.

## Features

- **Long-Range Redundancy**: Uses the rzip algorithm to efficiently compress large files with long-distance redundant data.
- **High Compatibility**: Fully compatible with `lrzip-next` (C implementation).
  - Can decompress files created by `lrzip`.
  - Files compressed by `lrzip-rust` can be decompressed by `lrzip`.
- **Safe & Fast**: Written in pure Rust with performance comparable to C (~80% speed).
- **Modern User Experience**:
  - Smooth progress bars with ETA and speed.
  - Coloring output and compression summaries.
  - Integrity verification (CRC32, MD5).

## Installation

```bash
cargo install --path .
```

## Usage

### Compression

Compress a file (defaults to LZMA backend):

```bash
lrzip-rust huge_file.bin
```

Specify a different backend (gzip or zstd):

```bash
lrzip-rust --backend zstd huge_file.bin
```

### Decompression

Decompress an `.lrz` file:

```bash
lrzip-rust -d huge_file.bin.lrz
```

### Options

| Flag | Description |
|------|-------------|
| `-d`, `--decompress` | Decompress input file. |
| `-o`, `--output <PATH>` | Specify output filename. |
| `-q`, `--quiet` | Suppress all output except errors. |
| `--info` | Show file information (headers, compression type). |
| `--backend <TYPE>` | Choose backend: `lzma` (default), `zstd`, `gzip`. |
| `--no-mmap` | Disable memory mapping (slower, but useful for pipes/special files). |

## Build

```bash
cargo build --release
```
