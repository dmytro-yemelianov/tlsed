//! Pure flight-order policy for the no-PSK, server-authenticated TLS client.
//! `verified` is evidence supplied by the endpoint after parsing and checking
//! the message. This guard performs no cryptographic or certificate verification.

/// Phases: 0=ServerHello, 1=EncryptedExtensions, 2=Certificate,
/// 3=CertificateVerify, 4=server Finished, 5=client Finished handoff,
/// 6=Established, 7=Failed. Internal events: 253=validated HRR,
/// 252=client Finished handed off, 255=fatal failure.
///
/// An accepted HRR leaves phase zero; the caller must atomically set `retried`.
/// Rejection returns no successor, so the endpoint must enter its failure path.
pub fn client_phase_next(phase: u8, message: u8, verified: bool, retried: bool) -> Option<u8> {
    if message == 255 {
        Some(7)
    } else if !verified {
        None
    } else if phase == 0 && message == 2 {
        Some(1)
    } else if phase == 0 && message == 253 && !retried {
        Some(0)
    } else if phase == 1 && message == 8 {
        Some(2)
    } else if phase == 2 && message == 11 {
        Some(3)
    } else if phase == 3 && message == 15 {
        Some(4)
    } else if phase == 4 && message == 20 {
        Some(5)
    } else if phase == 5 && message == 252 {
        Some(6)
    } else {
        None
    }
}
