# tls-core: experimental foundation

This `no_std`, safe-Rust crate supplies protocol components using the narrow
`tls-crypto` boundary and `zeroize`. It implements protected records through an
external provider, but is **not a TLS endpoint** and performs no certificate or
identity verification. Its typed key schedule provides Finished verification;
`tls-client` composes the actual authenticated connection. Six pure guards have linked
Lean proofs under recorded translation assumptions. Full component paths are
tested/modelled, and no external security audit is claimed.

The implemented surface is deliberately narrow:

- `wire::{Limits, Header, parse_header, parse_record}`: plaintext/ciphertext outer
  syntax and protocol/resource caps; borrowed bodies and exact incomplete-byte
  requirements. Plaintext legacy version is ignored on receive. Writers emit
  `0x0303`. Ciphertext remains unauthenticated bytes.
- `framing::Framer`: caller-owned reusable scratch buffer, one retained record,
  explicit consumption/backpressure, no allocation or amplification. Malformed
  wire input and incomplete EOF permanently fail it. Calling `consume_record`
  before completion returns a recoverable caller error without discarding input.
- `schedule::{record_count, ChunkSchedule}`: overflow-free count and greedy chunk
  lengths. Optimality concerns only fixed-capacity record count, not latency,
  padding, cryptography, or total TLS performance.
- `protected::{ProtectedWriter, ProtectedReader}`: caller-buffer AEAD record
  protection, strict inner type/padding limits, exact authenticated header and
  nonce discipline. Terminal failures wipe output/IV and retire the owned key.
- `handshake::Reassembler`: bounded u24 messages, work budgets, coalescing,
  retained-message backpressure and explicit record/key boundary checks.
- `counter::{WriteCounter, ReadCounter}`: separate mutable, nonclone counters;
  checked reservations retire their sequence even on future canceled/failed
  crypto attempts. Sending epochs stop at `2^48-1`; receiving epochs do not
  enforce that sending cap. A reservation is bookkeeping, not a protected record.
- `auth::{ClientAuthModel, transition, may_release}`: a small abstract client
  evidence sequence. The caller asserts externally verified events. This is not
  a handshake implementation or a public authenticated connection API.
- `hello`: caller-buffer ClientHello and borrowed ServerHello/EE/Certificate/
  CertificateVerify codecs with strict bounds and extension rules.
- `transcript::Transcript`: bounded streaming SHA256/384, snapshots and single
  HRR message_hash rewrite through maintained hash contexts.
- `key_schedule`: typed no-PSK traffic secrets, Finished checks, key/IV derivation
  and consuming traffic updates through maintained HKDF/HMAC.
- `client_policy::client_phase_next`: extracted/proved scalar client phase guard;
  verification evidence and atomic retry bookkeeping are separate obligations.

Example of syntactic bounded framing:

```rust
use tls_core::framing::{Framer, Status};
use tls_core::wire::{Limits, RecordKind};

let limits = Limits::new(RecordKind::Plaintext, 16)?;
let mut scratch = [0_u8; 21]; // five-byte header + configured body cap
let mut framer = Framer::new(&mut scratch, limits)?;
let progress = framer.push(&[22, 3, 3, 0, 3, 1, 2, 3])?;
assert_eq!(progress.status, Status::RecordReady);
assert_eq!(framer.record()?.unwrap().payload, &[1, 2, 3]);
// Enforce protocol state/body rules before routing these unauthenticated bytes.
framer.consume_record()?;
# Ok::<(), tls_core::Error>(())
```

For coalesced input, retain the unconsumed tail, inspect/consume each ready record,
then push that tail. An outstanding record makes `push` consume zero bytes.
Borrowed record views must end before mutation. Scratch must hold the entire
configured maximum wire record; smaller configurations allow smaller scratch.
Each call copies no more than one bounded record, even for large input slices.
`finish_input` identifies a partial record only; it cannot prove orderly TLS
shutdown. The separate protected-record/reassembly components enforce their own
documented rules. Plaintext body validation (CCS byte, alert values), endpoint
state-specific acceptance, certificate verification, KeyUpdate and fresh-key
installation belong to the implemented experimental `tls-client` connection.
The low-level framer alone does not enforce those endpoint rules.

The client dispatcher recognizes and drops permitted unencrypted CCS before
ciphertext deprotection, checking the single `0x01` body and the allowed handshake
window (RFC 9846 §5). The fixed ciphertext header parser intentionally rejects
CCS because CCS is not a ciphertext record; it is not a complete endpoint record
dispatcher.

The client installs fresh keys with counter rotation, selects conservative
provider-specific sending limits, reserves old-key space for KeyUpdate and
aborts on decryption failure. The conservative sequence implementation never
reserves `u64::MAX`; it can reserve `0..u64::MAX-1`. It accepts explicit resource
limits and does not select a cipher or infer cryptographic usage bounds.

Run regression and source checks from the repository root:

```sh
cargo fmt -p tls-core --check
cargo clippy -p tls-core --all-targets -- -D warnings
cargo test -p tls-core --locked
cargo build -p tls-core --example model_probe --locked
```

The deterministic correspondence CLI is
`target/debug/examples/model_probe MODE ARGS...`:

| Mode | Arguments | Output |
|---|---|---|
| `count` | `BYTES CAPACITY` (native usize) | decimal minimum count, or `error` |
| `handshake-total` | `BODY CAP` (native usize) | bounded total length, or `error` |
| `header` | `KIND TYPE VERSION LENGTH CAP` | `true`/`false`, or `error` for invalid numeric arguments/mode |
| `reserve` | `NEXT LIMIT` (u64) | incremented next value, or `error` |
| `rotate` | `EPOCH MAXIMUM` (u64) | incremented epoch, or `error` |
| `auth` | `STATE EVENT` | next state code, or `error` |
| `release` | `STATE AEAD_OK` (0/1) | `true`/`false`, or `error` |

Header kind: 0 plaintext, 1 ciphertext. Type is u8; version and length are u16;
cap is usize. A parsed cap exceeding the kind's protocol maximum yields `false`.
State codes: 0 start, 1 hello accepted, 2 identity verified, 3 signature verified,
4 established, 5 failed. Event codes: 0 hello accepted, 1 certificate and identity
verified, 2 CertificateVerify verified, 3 Finished verified, 4 abort, 5 AEAD failed.
Illegal events leave mutable state unchanged. Events 4/5 transition to failure
from every state. Release requires state 4 and successful AEAD evidence.

Executable comparison with Lean is evidence of tested correspondence, not formal
Rust refinement. See the repository proof ledger for exact claims. Fuzz harness
commands and remaining campaign limits are described in `../../fuzz/README.md`.
The separate `protected_probe inner-check TYPE CONTENT PADDING LIMIT` checks
numeric inner-record type/size rules against Lean. See `../../docs/PROTECTED_RECORDS.md`
and `../../docs/REASSEMBLY.md` for the real component APIs and caller obligations.
