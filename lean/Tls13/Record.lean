import Init

namespace Tls13

def maxU64 : Nat := 18446744073709551615

def reserveNext (next limit : Nat) : Option Nat :=
  if next < limit ∧ next < maxU64 then some (next + 1) else none

def rotateEpoch (epoch cap : Nat) : Option Nat :=
  if epoch < cap ∧ epoch < maxU64 then some (epoch + 1) else none

theorem reserveNext_safe (next limit after : Nat)
    (ok : reserveNext next limit = some after) :
    after = next + 1 ∧ next < after ∧ after ≤ limit ∧ after ≤ maxU64 := by
  unfold reserveNext at ok
  split at ok <;> simp_all <;> omega

theorem exhausted_sequence_rejected (next limit : Nat)
    (exhausted : limit ≤ next ∨ maxU64 ≤ next) : reserveNext next limit = none := by
  unfold reserveNext
  split <;> simp_all <;> omega

theorem rotateEpoch_safe (epoch cap after : Nat)
    (ok : rotateEpoch epoch cap = some after) :
    after = epoch + 1 ∧ epoch < after ∧ after ≤ cap ∧ after ≤ maxU64 := by
  unfold rotateEpoch at ok
  split at ok <;> simp_all <;> omega

theorem exhausted_epoch_rejected (epoch cap : Nat)
    (exhausted : cap ≤ epoch ∨ maxU64 ≤ epoch) : rotateEpoch epoch cap = none := by
  unfold rotateEpoch
  split <;> simp_all <;> omega

/-- Atomic consumption: returned state must be installed before reserving again. -/
inductive Reservations (limit : Nat) : Nat → Nat → List Nat → Prop
  | nil (start) : Reservations limit start start []
  | cons {start next finish rest} : reserveNext start limit = some next →
      Reservations limit next finish rest →
      Reservations limit start finish (start :: rest)

theorem reservations_monotone {limit start finish records : _}
    (trace : Reservations limit start finish records) : start ≤ finish := by
  induction trace with
  | nil => omega
  | cons ok _ ih =>
    have := reserveNext_safe _ _ _ ok
    omega

theorem reservation_in_range {limit start finish records : _}
    (trace : Reservations limit start finish records) :
    ∀ x ∈ records, start ≤ x ∧ x < finish := by
  induction trace with
  | nil => simp
  | @cons start next finish rest ok tail ih =>
    intro x hx
    simp only [List.mem_cons] at hx
    have safe := reserveNext_safe _ _ _ ok
    have mono := reservations_monotone tail
    rcases hx with h | h
    · subst x; omega
    · have := ih x h; omega

/-- A consumed sequence number is never used twice within one modeled epoch. -/
theorem reservations_unique {limit start finish records : _}
    (trace : Reservations limit start finish records) : records.Nodup := by
  induction trace with
  | nil => simp
  | @cons start next finish rest ok tail ih =>
    apply List.nodup_cons.mpr
    constructor
    · intro member
      have := reservation_in_range tail start member
      have := reserveNext_safe _ _ _ ok
      omega
    · exact ih

/-- Distinct epochs separate nonce coordinates even when sequence resets to zero. -/
theorem rotated_coordinates_distinct (epoch cap after oldSeq newSeq : Nat)
    (ok : rotateEpoch epoch cap = some after) :
    (epoch, oldSeq) ≠ (after, newSeq) := by
  have := rotateEpoch_safe _ _ _ ok
  intro eq
  have := congrArg Prod.fst eq
  simp only at this
  omega

end Tls13
