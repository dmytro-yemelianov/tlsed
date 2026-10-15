//! Plain deterministic CLI for cross-language tests; not a TLS client.
use tls_core::auth::{Event, State, may_release, transition};
use tls_core::counter::{reserve_next, rotate_epoch};
use tls_core::handshake::checked_handshake_total;
use tls_core::schedule::record_count;
use tls_core::wire::{Header, Limits, RecordKind};

fn state(value: u8) -> Option<State> {
    Some(match value {
        0 => State::Start,
        1 => State::HelloAccepted,
        2 => State::IdentityVerified,
        3 => State::SignatureVerified,
        4 => State::Established,
        5 => State::Failed,
        _ => return None,
    })
}
fn event(value: u8) -> Option<Event> {
    Some(match value {
        0 => Event::HelloAccepted,
        1 => Event::CertificateAndIdentityVerified,
        2 => Event::CertificateVerifyVerified,
        3 => Event::FinishedVerified,
        4 => Event::Abort,
        5 => Event::AeadFailed,
        _ => return None,
    })
}
fn run(args: &[String]) -> Option<String> {
    match args.first()?.as_str() {
        "count" if args.len() == 3 => Some(
            record_count(args[1].parse().ok()?, args[2].parse().ok()?)
                .ok()?
                .to_string(),
        ),
        "handshake-total" if args.len() == 3 => {
            Some(checked_handshake_total(args[1].parse().ok()?, args[2].parse().ok()?)?.to_string())
        }
        "reserve" if args.len() == 3 => {
            Some(reserve_next(args[1].parse().ok()?, args[2].parse().ok()?)?.to_string())
        }
        "rotate" if args.len() == 3 => {
            Some(rotate_epoch(args[1].parse().ok()?, args[2].parse().ok()?)?.to_string())
        }
        "header" if args.len() == 6 => {
            let kind = match args[1].as_str() {
                "0" => RecordKind::Plaintext,
                "1" => RecordKind::Ciphertext,
                _ => return None,
            };
            let limits = Limits::new(kind, args[5].parse().ok()?);
            let header = Header {
                content_type: args[2].parse().ok()?,
                legacy_version: args[3].parse().ok()?,
                length: args[4].parse().ok()?,
            };
            Some(
                limits
                    .and_then(|limit| header.validate(limit))
                    .is_ok()
                    .to_string(),
            )
        }
        "auth" if args.len() == 3 => Some(
            (transition(state(args[1].parse().ok()?)?, event(args[2].parse().ok()?)?).ok()? as u8)
                .to_string(),
        ),
        "release" if args.len() == 3 => {
            let checked = match args[2].as_str() {
                "0" => false,
                "1" => true,
                _ => return None,
            };
            Some(
                if may_release(state(args[1].parse().ok()?)?, checked) {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            )
        }
        _ => None,
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    println!("{}", run(&args).unwrap_or_else(|| "error".to_string()));
}
