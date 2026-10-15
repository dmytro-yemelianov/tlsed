//! Copy cost per byte against the memory footprint the copies rotate through.
//!
//! Question: at a fixed copy size, does the cost per byte depend on how much memory the copies
//! spread over (cache state), with no TLS code involved? Each copy is `copy_from_slice`, which
//! calls the platform `memcpy`. Indices come from a precomputed random sequence, so the timer
//! measures copies only and access order defeats sequential prefetching.
//!
//! Modes: `dst` rotates the destination over the footprint, `src` rotates the source, and
//! `both` rotates both. The rotating side is cold between uses once the footprint exceeds the
//! cache that holds it.

use std::hint::black_box;
use std::time::Instant;

const TARGET_BYTES: usize = 64 << 20;
const REPEATS: usize = 7;

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Buffers filled with a value, so every page is resident before timing.
fn pool(buffers: usize, size: usize) -> Vec<Vec<u8>> {
    (0..buffers)
        .map(|i| vec![(i % 251) as u8 + 1; size])
        .collect()
}

/// Nanoseconds per byte for each timed repeat (the warm-up repeat is discarded).
fn measure(size: usize, footprint: usize, mode: &str) -> Vec<f64> {
    let buffers = (footprint / size).max(1);
    let rotate_src = mode == "src" || mode == "both";
    let rotate_dst = mode == "dst" || mode == "both";
    let src = pool(if rotate_src { buffers } else { 1 }, size);
    let mut dst = pool(if rotate_dst { buffers } else { 1 }, size);
    let ops = (TARGET_BYTES / size).max(4096);
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15 ^ footprint as u64);
    let order: Vec<(usize, usize)> = (0..ops)
        .map(|_| {
            let i = if rotate_src {
                (rng.next() as usize) % buffers
            } else {
                0
            };
            let j = if rotate_dst {
                (rng.next() as usize) % buffers
            } else {
                0
            };
            (i, j)
        })
        .collect();
    let mut out = Vec::with_capacity(REPEATS);
    for repeat in 0..=REPEATS {
        let start = Instant::now();
        for &(i, j) in &order {
            dst[j].copy_from_slice(&src[i]);
        }
        let elapsed = start.elapsed().as_nanos() as f64;
        black_box(&dst);
        if repeat > 0 {
            out.push(elapsed / (ops * size) as f64);
        }
    }
    out
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    values[values.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let option = |key: &str, default: &str| -> String {
        match args.iter().position(|x| x == key) {
            Some(i) => args.get(i + 1).cloned().unwrap_or_else(|| default.into()),
            None => default.into(),
        }
    };
    let size: usize = option("--size", "16384").parse().expect("size");
    let mode = option("--mode", "dst");
    if !matches!(mode.as_str(), "dst" | "src" | "both") {
        panic!("invalid mode");
    }
    let footprints: Vec<usize> = option("--footprints", "16384,262144,4194304,67108864,268435456")
        .split(',')
        .map(|f| f.parse().expect("footprint"))
        .collect();
    println!(
        "mode,size,footprint_bytes,buffers,ns_per_byte_median,ns_per_byte_min,ns_per_byte_max"
    );
    for footprint in footprints {
        let samples = measure(size, footprint, &mode);
        let (min, max) = (
            samples.iter().copied().fold(f64::INFINITY, f64::min),
            samples.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        );
        println!(
            "{mode},{size},{footprint},{},{:.5},{:.5},{:.5}",
            (footprint / size).max(1),
            median(samples),
            min,
            max
        );
    }
}
