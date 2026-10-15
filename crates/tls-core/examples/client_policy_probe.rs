//! Numeric flight-policy probe. It cannot construct an authenticated connection.
use tls_core::client_policy::client_phase_next;
fn run(args: &[String]) -> Option<String> {
    if args.len() != 5 || args[0] != "client-phase" {
        return None;
    }
    let flag = |s: &str| match s {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    };
    client_phase_next(
        args[1].parse().ok()?,
        args[2].parse().ok()?,
        flag(&args[3])?,
        flag(&args[4])?,
    )
    .map(|phase| phase.to_string())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    println!("{}", run(&args).unwrap_or_else(|| "error".to_string()));
}
