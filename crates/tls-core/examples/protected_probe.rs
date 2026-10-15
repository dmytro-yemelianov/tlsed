//! Deterministic structural model CLI, not a TLS endpoint.
use tls_core::protected::{inner_length, valid_content_type};

fn run(args: &[String]) -> Option<String> {
    if args.len() != 5 || args[0] != "inner-check" {
        return None;
    }
    let content_type: u8 = args[1].parse().ok()?;
    let content_len: usize = args[2].parse().ok()?;
    let padding_len: usize = args[3].parse().ok()?;
    let inner_limit: usize = args[4].parse().ok()?;
    Some(
        (valid_content_type(content_type, content_len)
            && inner_length(content_len, padding_len, inner_limit).is_some())
        .to_string(),
    )
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    println!("{}", run(&args).unwrap_or_else(|| "error".to_string()));
}
