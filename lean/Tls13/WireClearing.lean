import Tls13.Zeroization

namespace Tls13

/-- Observable memory effect of one zero-byte store. Volatility is not modeled. -/
def wireZeroByte (memory : PlainMemory) (position : Nat) : PlainMemory :=
  fun i => if i = position then 0 else memory i

/-- A sequential clear, modeled independently of the declarative range fill. -/
def wireClearLoop (memory : PlainMemory) (start : Nat) : Nat → PlainMemory
  | 0 => memory
  | count + 1 => wireClearLoop (wireZeroByte memory start) (start + 1) count

/-- Bulk fill and sequential clearing have identical observable byte states.
This says nothing about volatile stores, compiler elimination, or erasure. -/
theorem wireClearLoop_equals_fill (memory : PlainMemory) (start count : Nat) :
    wireClearLoop memory start count = consumedPlaintext memory start count := by
  induction count generalizing memory start with
  | zero => simpa [wireClearLoop] using (consumedPlaintext_zero memory start).symm
  | succ count ih =>
    rw [wireClearLoop, ih]
    funext i
    by_cases first : i = start
    · subst i
      simp [consumedPlaintext, wireZeroByte, show ¬ start + 1 ≤ start by omega]
    · by_cases inside : start + 1 ≤ i ∧ i < start + 1 + count
      · have whole : start ≤ i ∧ i < start + (count + 1) := by omega
        simp [consumedPlaintext, inside, whole]
      · have outside : ¬ (start ≤ i ∧ i < start + (count + 1)) := by omega
        simp [consumedPlaintext, wireZeroByte, first, inside, outside]

/-- Range fill used after bytes have been copied to the transport recipient. -/
def publicWireDrain (memory : PlainMemory) (length offset requested : Nat) : PlainMemory :=
  consumedPlaintext memory offset (readAmount length offset requested)

theorem publicWireDrain_bounds (length offset requested : Nat) (valid : offset ≤ length) :
    readAmount length offset requested ≤ requested ∧
    offset ≤ offset + readAmount length offset requested ∧
    offset + readAmount length offset requested ≤ length := by
  exact readAmount_bounds length offset requested valid

theorem publicWireDrain_clears_consumed (memory : PlainMemory) (length offset requested i : Nat)
    (lower : offset ≤ i) (upper : i < offset + readAmount length offset requested) :
    publicWireDrain memory length offset requested i = 0 := by
  exact consumedPlaintext_inside memory offset _ i lower upper

theorem publicWireDrain_preserves_other (memory : PlainMemory) (length offset requested i : Nat)
    (outside : i < offset ∨ offset + readAmount length offset requested ≤ i) :
    publicWireDrain memory length offset requested i = memory i := by
  exact consumedPlaintext_outside memory offset _ i outside

theorem publicWireDrain_zero (memory : PlainMemory) (length offset : Nat) :
    publicWireDrain memory length offset 0 = memory := by
  exact (readPlaintext_zero_request memory length offset).2

/-- A consumed-prefix invariant is enough; the live suffix may contain any bytes. -/
theorem publicWireDrain_prefix (memory : PlainMemory) (length offset requested : Nat)
    (cleanPrefix : ∀ i, i < offset → memory i = 0) :
    ∀ i, i < offset + readAmount length offset requested →
      publicWireDrain memory length offset requested i = 0 := by
  intro i hi
  by_cases old : i < offset
  · rw [publicWireDrain_preserves_other memory length offset requested i (Or.inl old)]
    exact cleanPrefix i old
  · exact publicWireDrain_clears_consumed memory length offset requested i (by omega) hi

theorem publicWireDrain_complete (memory : PlainMemory) (length offset requested : Nat)
    (valid : offset ≤ length) (enough : length - offset ≤ requested)
    (cleanPrefix : ∀ i, i < offset → memory i = 0) :
    offset + readAmount length offset requested = length ∧
    ∀ i, i < length → publicWireDrain memory length offset requested i = 0 := by
  have done : offset + readAmount length offset requested = length := by
    simp only [readAmount, Nat.min_def]
    split <;> omega
  refine ⟨done, ?_⟩
  intro i hi
  exact publicWireDrain_prefix memory length offset requested cleanPrefix i (by omega)

/-- Exactly the initially nonzero consumed bytes change value. -/
theorem wireFill_changes_exactly (memory : PlainMemory) (start count i : Nat) :
    consumedPlaintext memory start count i ≠ memory i ↔
    start ≤ i ∧ i < start + count ∧ memory i ≠ 0 := by
  by_cases inside : start ≤ i ∧ i < start + count
  · rw [consumedPlaintext_inside memory start count i inside.1 inside.2]
    constructor
    · intro changed
      exact ⟨inside.1, inside.2, Ne.symm changed⟩
    · intro changed
      exact Ne.symm changed.2.2
  · rw [consumedPlaintext_outside memory start count i (by omega)]
    simp only [ne_self_iff_false, false_iff]
    intro changed
    exact inside ⟨changed.1, changed.2.1⟩

/-- Any operation meeting the live zero-byte contract must change every byte
that the range fill changes. This is minimal changed support, not CPU work. -/
theorem wireFill_minimal_changed_footprint (before after : PlainMemory) (start count : Nat)
    (contract : ∀ i, start ≤ i → i < start + count → after i = 0) :
    ∀ i, consumedPlaintext before start count i ≠ before i → after i ≠ before i := by
  intro i changed
  have ⟨lower, upper, nonzero⟩ := (wireFill_changes_exactly before start count i).mp changed
  rw [contract i lower upper]
  exact Ne.symm nonzero

/-- If consumed bytes initially are nonzero, every one must be in any claimed
write footprint. Already-zero bytes need not be stored again merely to meet
the final-state contract. The footprint says nothing about machine instructions. -/
theorem wireFill_mandatory_footprint (before after : PlainMemory) (start count : Nat)
    (touched : Nat → Prop)
    (contract : ∀ i, start ≤ i → i < start + count → after i = 0)
    (footprint : ∀ i, ¬ touched i → after i = before i)
    (nonzero : ∀ i, start ≤ i → i < start + count → before i ≠ 0) :
    ∀ i, start ≤ i → i < start + count → touched i := by
  intro i lower upper
  by_cases hit : touched i
  · exact hit
  · have old := footprint i hit
    have cleared := contract i lower upper
    exact False.elim (nonzero i lower upper (by rw [← old, cleared]))

end Tls13
