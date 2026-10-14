import Tls13

/-- The differential executable restricts natural arguments to Rust's 64-bit domain.
The theorems themselves hold for arbitrary naturals. -/
def boundedNat (s : String) (maximum : Nat := Tls13.maxU64) : Option Nat := do
  let n ← s.toNat?
  if n ≤ maximum then some n else none

def showResult (result : Option Nat) : String :=
  match result with
  | some n => toString n
  | none => "error"

def runCommand (args : List String) : String :=
  match args with
  | ["count", n, limit] => showResult do
    let n ← boundedNat n
    let limit ← boundedNat limit
    if limit > 0 then some (Tls13.recordCount n limit) else none
  | ["label-size", output, label, context] => showResult do
    let output ← boundedNat output
    let label ← boundedNat label
    let context ← boundedNat context
    Tls13.hkdfLabelSize output label context
  | ["handshake-total", body, cap] => showResult do
    let body ← boundedNat body
    let cap ← boundedNat cap
    Tls13.checkedHandshakeTotal body cap
  | ["inner-check", kind, content, padding, limit] =>
    match boundedNat kind 255, boundedNat content, boundedNat padding, boundedNat limit with
    | some kind, some content, some padding, some limit =>
      toString (Tls13.innerAccepted kind content padding limit)
    | _, _, _, _ => "error"
  | ["reserve", next, limit] => showResult do
    let next ← boundedNat next
    let limit ← boundedNat limit
    Tls13.reserveNext next limit
  | ["rotate", epoch, cap] => showResult do
    let epoch ← boundedNat epoch
    let cap ← boundedNat cap
    Tls13.rotateEpoch epoch cap
  | ["client-phase", phase, message, verified, retried] => showResult do
    let phase ← boundedNat phase 255
    let message ← boundedNat message 255
    let verified ← boundedNat verified 1
    let retried ← boundedNat retried 1
    Tls13.clientPhaseNext phase message (verified == 1) (retried == 1)
  | ["auth", state, event] => showResult do
    let state ← boundedNat state 5
    let event ← boundedNat event 5
    Tls13.authStep state event
  | ["release", state, aead] =>
    match boundedNat state 5, boundedNat aead 1 with
    | some state, some aead => toString (Tls13.releaseAllowed state (aead == 1))
    | _, _ => "error"
  | ["header", mode, kind, version, length, cap] =>
    match boundedNat mode 1, boundedNat kind 255, boundedNat version 65535,
        boundedNat length 65535, boundedNat cap with
    | some mode, some kind, some version, some length, some cap =>
      toString (Tls13.headerAccepted (mode == 1) ⟨kind, version, length⟩ cap)
    | _, _, _, _, _ => "error"
  | _ => "error"

def main (args : List String) : IO Unit := do
  let out ← IO.getStdout
  out.putStrLn (runCommand args)
