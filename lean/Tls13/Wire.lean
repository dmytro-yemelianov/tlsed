import Init

namespace Tls13

/-- Pure numeric model of the five-byte TLS record header. -/
structure Header where
  kind : Nat
  version : Nat
  length : Nat
  deriving DecidableEq, Repr

def protocolCap (ciphertext : Bool) : Nat := if ciphertext then 16640 else 16384

def headerAccepted (ciphertext : Bool) (h : Header) (cap : Nat) : Bool :=
  decide (cap ≤ protocolCap ciphertext ∧ h.length ≤ cap ∧
    if ciphertext then h.kind = 23 ∧ h.version = 771 ∧ 0 < h.length
    else (h.kind = 20 ∧ h.length = 1) ∨ (h.kind = 21 ∧ h.length = 2) ∨
      (h.kind = 22 ∧ 0 < h.length))

theorem accepted_length_bounded (mode : Bool) (h : Header) (cap : Nat)
    (ok : headerAccepted mode h cap = true) :
    h.length ≤ cap ∧ cap ≤ protocolCap mode := by
  simp only [headerAccepted, decide_eq_true_eq] at ok
  exact ⟨ok.2.1, ok.1⟩

theorem oversized_rejected (mode : Bool) (h : Header) (cap : Nat)
    (tooLarge : cap < h.length) : headerAccepted mode h cap = false := by
  simp only [headerAccepted, decide_eq_false_iff_not]
  omega

theorem invalid_cap_rejected (mode : Bool) (h : Header) (cap : Nat)
    (tooLarge : protocolCap mode < cap) : headerAccepted mode h cap = false := by
  simp only [headerAccepted, decide_eq_false_iff_not]
  omega

theorem ciphertext_header_guard (h : Header) (cap : Nat)
    (ok : headerAccepted true h cap = true) :
    h.kind = 23 ∧ h.version = 771 ∧ 0 < h.length := by
  simp only [headerAccepted, decide_eq_true_eq, ite_true] at ok
  exact ok.2.2

/-- Checked cursor arithmetic. Input length is external, never an untrusted allocation. -/
def readRange (inputLength position count : Nat) : Option Nat :=
  if position ≤ inputLength ∧ count ≤ inputLength - position then some (position + count)
  else none

theorem readRange_safe (inputLength position count finish : Nat)
    (ok : readRange inputLength position count = some finish) :
    position ≤ finish ∧ finish ≤ inputLength ∧ finish = position + count := by
  unfold readRange at ok
  split at ok <;> simp_all <;> omega

theorem readRange_rejects_truncation (inputLength position count : Nat)
    (short : inputLength < position + count) :
    readRange inputLength position count = none := by
  unfold readRange
  split <;> simp_all <;> omega

/-- Wire bytes are modeled as bounded naturals, independent of machine integers. -/
def encodeHeader (h : Header) : List Nat :=
  [h.kind, h.version / 256, h.version % 256, h.length / 256, h.length % 256]

def decodeHeader : List Nat → Option Header
  | [kind, vhi, vlo, lhi, llo] =>
    if kind < 256 ∧ vhi < 256 ∧ vlo < 256 ∧ lhi < 256 ∧ llo < 256 then
      some ⟨kind, 256 * vhi + vlo, 256 * lhi + llo⟩
    else none
  | _ => none

theorem encodeHeader_size (h : Header) : (encodeHeader h).length = 5 := by rfl

theorem decode_encode_header (h : Header)
    (kindBound : h.kind < 256) (versionBound : h.version < 65536)
    (lengthBound : h.length < 65536) : decodeHeader (encodeHeader h) = some h := by
  have vhi : h.version / 256 < 256 := (Nat.div_lt_iff_lt_mul (by decide)).mpr versionBound
  have lhi : h.length / 256 < 256 := (Nat.div_lt_iff_lt_mul (by decide)).mpr lengthBound
  have vlo := Nat.mod_lt h.version (by decide : 0 < 256)
  have llo := Nat.mod_lt h.length (by decide : 0 < 256)
  simp [encodeHeader, decodeHeader, kindBound, vhi, lhi, vlo, llo,
    Nat.div_add_mod]

end Tls13
