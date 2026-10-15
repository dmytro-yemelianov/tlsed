//! Numeric structural model CLI; no secret derivation or endpoint behavior.
use tls_core::key_schedule::hkdf_label_encoded_len;
fn run(args: &[String]) -> Option<String> {
    if args.len() != 4 || args[0] != "label-size" {
        return None;
    }
    hkdf_label_encoded_len(
        args[1].parse().ok()?,
        args[2].parse().ok()?,
        args[3].parse().ok()?,
    )
    .map(|length| length.to_string())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    println!("{}", run(&args).unwrap_or_else(|| "error".to_string()));
}
