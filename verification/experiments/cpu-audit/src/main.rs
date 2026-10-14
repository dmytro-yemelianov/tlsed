use std::hint::black_box;
use std::time::Instant;
use zeroize::Zeroize;
#[inline(never)]
fn scalar(bytes: &mut [u8]) {
    bytes.zeroize();
}
#[inline(never)]
fn words(bytes: &mut [u8]) {
    let (head, mid, tail) = bytemuck::pod_align_to_mut::<u8, u128>(bytes);
    head.zeroize();
    mid.zeroize();
    tail.zeroize();
}
#[inline(never)]
fn blocks<const N: usize>(bytes: &mut [u8]) {
    let (head, mid, tail) = bytemuck::pod_align_to_mut::<u8, u128>(bytes);
    head.zeroize();
    let (groups, rest) = mid.as_chunks_mut::<N>();
    groups.iter_mut().zeroize();
    rest.zeroize();
    tail.zeroize();
}
#[inline(never)]
fn neon(bytes: &mut [u8]) {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        let (head, mid, tail) =
            bytemuck::pod_align_to_mut::<u8, core::arch::aarch64::uint8x16_t>(bytes);
        head.zeroize();
        mid.iter_mut().zeroize();
        tail.zeroize();
    }
    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
    words(bytes);
}
type Variant = (&'static str, fn(&mut [u8]));
fn variants() -> [Variant; 6] {
    [
        ("byte_reference", scalar),
        ("current_u128", words),
        ("block2", blocks::<2>),
        ("block4", blocks::<4>),
        ("block8", blocks::<8>),
        ("neon", neon),
    ]
}
fn validate() {
    for offset in 0..32 {
        for size in (0..=257).chain([1023, 1024, 1025, 16383, 16384, 16385, 65539, 65540]) {
            let start = 16 + offset;
            let mut expected = vec![0xa5; start + size + 32];
            expected[start..start + size].fill(0);
            for (name, wipe) in variants() {
                let mut data = vec![0xa5; start + size + 32];
                wipe(&mut data[start..start + size]);
                assert_eq!(data, expected, "{name} size={size} offset={offset}");
            }
        }
    }
}
fn main() {
    validate();
    let repeat: usize = std::env::args()
        .nth(1)
        .unwrap_or("0".into())
        .parse()
        .unwrap();
    println!("variant,size,offset,iterations,sample,elapsed_ns");
    let variants = variants();
    for size in [0, 1, 15, 16, 17, 64, 1024, 16384, 65540] {
        let iterations = if size >= 16384 { 256 } else { 4096 };
        for offset in [0, 1, 15] {
            let start = 16 + offset;
            let mut data = vec![0xa5; start + size + 32];
            for sample in 0..35 {
                for step in 0..variants.len() {
                    let (name, wipe) = variants[(repeat + sample + step) % variants.len()];
                    data[start..start + size].fill(0xa5);
                    let now = Instant::now();
                    for _ in 0..iterations {
                        wipe(black_box(&mut data[start..start + size]));
                    }
                    let elapsed = now.elapsed().as_nanos();
                    assert!(data[start..start + size].iter().all(|&b| b == 0));
                    assert!(
                        data[..start]
                            .iter()
                            .chain(data[start + size..].iter())
                            .all(|&b| b == 0xa5)
                    );
                    black_box(&data);
                    if sample >= 5 {
                        println!(
                            "{name},{size},{offset},{iterations},{},{elapsed}",
                            sample - 5
                        );
                    }
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn exact_ranges() {
        super::validate();
    }
}
