import Tls13.Record
import Tls13.Handshake

namespace Tls13

/-- Exact TLS HkdfLabel size guard, including the six-byte "tls13 " prefix. -/
def hkdfLabelSize (outputLength labelLength contextLength : Nat) : Option Nat :=
  if outputLength ≤ 65535 ∧ 1 ≤ labelLength ∧ labelLength ≤ 249 ∧ contextLength ≤ 255 then
    some (10 + labelLength + contextLength)
  else none

theorem hkdfLabelSize_bounds (outputLength labelLength contextLength size : Nat)
    (ok : hkdfLabelSize outputLength labelLength contextLength = some size) :
    outputLength ≤ 65535 ∧ 1 ≤ labelLength ∧ 6 + labelLength ≤ 255 ∧
    contextLength ≤ 255 ∧ size = 10 + labelLength + contextLength ∧ size ≤ 514 := by
  unfold hkdfLabelSize at ok
  split at ok <;> simp_all <;> omega

theorem hkdfLabelSize_rejects (outputLength labelLength contextLength : Nat)
    (invalid : 65535 < outputLength ∨ labelLength = 0 ∨ 249 < labelLength ∨ 255 < contextLength) :
    hkdfLabelSize outputLength labelLength contextLength = none := by
  unfold hkdfLabelSize
  split <;> simp_all <;> omega

def tls13LabelPrefix : List Nat := [116, 108, 115, 49, 51, 32]

/-- Numeric-byte serialization; input byte ranges are external to its length proof. -/
def encodeHkdfLabel (outputLength : Nat) (label context : List Nat) : List Nat :=
  [outputLength / 256, outputLength % 256, 6 + label.length] ++
    tls13LabelPrefix ++ label ++ [context.length] ++ context

theorem encodeHkdfLabel_length (outputLength : Nat) (label context : List Nat) :
    (encodeHkdfLabel outputLength label context).length = 10 + label.length + context.length := by
  simp [encodeHkdfLabel, tls13LabelPrefix]
  omega

theorem encodeHkdfLabel_fits (outputLength : Nat) (label context : List Nat) (size : Nat)
    (ok : hkdfLabelSize outputLength label.length context.length = some size) :
    (encodeHkdfLabel outputLength label context).length = size ∧ size ≤ 514 := by
  have bounds := hkdfLabelSize_bounds outputLength label.length context.length size ok
  rw [encodeHkdfLabel_length]
  omega

/-- Any layout carrying the mandatory fixed-width fields and complete label/context
has at least this footprint. This does not allow changing/compressing the TLS format. -/
theorem hkdfLabel_footprint_minimal (labelLength contextLength : Nat)
    (outputField labelLengthField labelPrefix label contextLengthField context : List Nat)
    (outputBytes : 2 ≤ outputField.length) (labelLengthBytes : 1 ≤ labelLengthField.length)
    (prefixBytes : 6 ≤ labelPrefix.length) (labelBytes : labelLength ≤ label.length)
    (contextLengthBytes : 1 ≤ contextLengthField.length) (contextBytes : contextLength ≤ context.length) :
    10 + labelLength + contextLength ≤
      (outputField ++ labelLengthField ++ labelPrefix ++ label ++ contextLengthField ++ context).length := by
  simp only [List.length_append]
  omega

inductive TrafficDirection where
  | client
  | server
  deriving DecidableEq, Repr

inductive TrafficStage where
  | handshake
  | application
  deriving DecidableEq, Repr

structure SecretCoordinate where
  direction : TrafficDirection
  stage : TrafficStage
  epoch : Nat
  deriving DecidableEq, Repr

/-- Secret selection includes direction, stage, and epoch, independently of bytes. -/
def selectSecret (stored requested : SecretCoordinate) : Option SecretCoordinate :=
  if stored = requested then some stored else none

theorem selectedSecret_matches (stored requested result : SecretCoordinate)
    (ok : selectSecret stored requested = some result) :
    result = stored ∧ stored.direction = requested.direction ∧ stored.stage = requested.stage ∧
    stored.epoch = requested.epoch := by
  unfold selectSecret at ok
  split at ok <;> simp_all

theorem wrong_secret_coordinate_rejected (stored requested : SecretCoordinate)
    (wrong : stored.direction ≠ requested.direction ∨ stored.stage ≠ requested.stage ∨
      stored.epoch ≠ requested.epoch) : selectSecret stored requested = none := by
  have unequal : stored ≠ requested := by intro eq; subst stored; simp at wrong
  simp [selectSecret, unequal]

/-- KeyUpdate is application-only; this models coordinates, not HKDF security. -/
def updateTrafficCoordinate (current : SecretCoordinate) (cap : Nat) : Option SecretCoordinate := do
  if current.stage = .application then
    let epoch ← rotateEpoch current.epoch cap
    some { current with epoch := epoch }
  else none

theorem traffic_update_monotone (current next : SecretCoordinate) (cap : Nat)
    (ok : updateTrafficCoordinate current cap = some next) :
    next.direction = current.direction ∧ next.stage = .application ∧
    next.epoch = current.epoch + 1 ∧ current.epoch < next.epoch ∧
    next.epoch ≤ cap ∧ next.epoch ≤ maxU64 := by
  unfold updateTrafficCoordinate at ok
  split at ok <;> simp_all
  cases rotated : rotateEpoch current.epoch cap with
  | none => simp [rotated] at ok
  | some epoch =>
    simp only [rotated, Option.bind_some, Option.some.injEq] at ok
    subst next
    have safe := rotateEpoch_safe current.epoch cap epoch rotated
    simp_all
    omega

theorem handshake_key_cannot_update (current : SecretCoordinate) (cap : Nat)
    (handshake : current.stage = .handshake) : updateTrafficCoordinate current cap = none := by
  simp [updateTrafficCoordinate, handshake]

/-- A failed Finished check poisons the modeled authentication state. -/
def finishAuthentication (state : Nat) (verified : Bool) : Nat :=
  if verified then (authStep state 3).getD 5 else 5

theorem failed_finished_blocks_release (state : Nat) (aeadOk : Bool) :
    releaseAllowed (finishAuthentication state false) aeadOk = false := by
  simp [finishAuthentication, releaseAllowed]

theorem finished_establishment_requires_stage (state : Nat) (verified : Bool)
    (ok : finishAuthentication state verified = 4) : state = 3 ∧ verified = true := by
  unfold finishAuthentication at ok
  split at ok <;> simp_all
  cases transition : authStep state 3 with
  | none => simp [transition] at ok
  | some next =>
    simp [transition] at ok
    have shape := authStep_characterization state 3 next transition
    omega

end Tls13
