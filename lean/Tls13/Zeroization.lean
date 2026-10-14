import Init

namespace Tls13

/-- Byte-addressed model. Only indices below `loan` belong to caller storage.
No aliasing, concurrent mutation, or compiler-level erasure claim is modeled. -/
abbrev PlainMemory := Nat → UInt8

/-- Successful record opening preserves content and clears the rest of the loan. -/
def openedPlaintext (memory : PlainMemory) (loan content : Nat) : PlainMemory :=
  fun i => if content ≤ i ∧ i < loan then 0 else memory i

def readAmount (content offset requested : Nat) : Nat :=
  min requested (content - offset)

/-- A read copies its old bytes to the caller before applying this exact-range wipe. -/
def consumedPlaintext (memory : PlainMemory) (offset amount : Nat) : PlainMemory :=
  fun i => if offset ≤ i ∧ i < offset + amount then 0 else memory i

/-- The unread content can contain arbitrary bytes. Both other regions are zero. -/
def CleanPlaintext (memory : PlainMemory) (loan content offset : Nat) : Prop :=
  offset ≤ content ∧ content ≤ loan ∧
  (∀ i, i < offset → memory i = 0) ∧
  (∀ i, content ≤ i → i < loan → memory i = 0)

theorem openedPlaintext_content (memory : PlainMemory) (loan content i : Nat)
    (inside : i < content) : openedPlaintext memory loan content i = memory i := by
  simp [openedPlaintext, show ¬ content ≤ i by omega]

theorem openedPlaintext_tail (memory : PlainMemory) (loan content i : Nat)
    (tail : content ≤ i) (inside : i < loan) :
    openedPlaintext memory loan content i = 0 := by
  simp [openedPlaintext, tail, inside]

theorem openedPlaintext_clean (memory : PlainMemory) (loan content : Nat)
    (fits : content ≤ loan) : CleanPlaintext (openedPlaintext memory loan content) loan content 0 := by
  refine ⟨by omega, fits, ?_, ?_⟩
  · intro i hi
    omega
  · intro i hi hj
    exact openedPlaintext_tail memory loan content i hi hj

theorem readAmount_bounds (content offset requested : Nat) (valid : offset ≤ content) :
    readAmount content offset requested ≤ requested ∧
    offset ≤ offset + readAmount content offset requested ∧
    offset + readAmount content offset requested ≤ content := by
  simp only [readAmount, Nat.min_def]
  split <;> omega

/-- Representable loan length suffices to make the offset addition nonoverflowing. -/
theorem readAmount_machine_bound (loan content offset requested maximum : Nat)
    (valid : offset ≤ content) (fits : content ≤ loan) (representable : loan ≤ maximum) :
    offset + readAmount content offset requested ≤ maximum := by
  have := readAmount_bounds content offset requested valid
  omega

theorem consumedPlaintext_inside (memory : PlainMemory) (offset amount i : Nat)
    (lower : offset ≤ i) (upper : i < offset + amount) :
    consumedPlaintext memory offset amount i = 0 := by
  simp [consumedPlaintext, lower, upper]

theorem consumedPlaintext_outside (memory : PlainMemory) (offset amount i : Nat)
    (outside : i < offset ∨ offset + amount ≤ i) :
    consumedPlaintext memory offset amount i = memory i := by
  have : ¬ (offset ≤ i ∧ i < offset + amount) := by omega
  simp [consumedPlaintext, this]

theorem consumedPlaintext_zero (memory : PlainMemory) (offset : Nat) :
    consumedPlaintext memory offset 0 = memory := by
  funext i
  simp [consumedPlaintext]
  omega

theorem readPlaintext_zero_request (memory : PlainMemory) (content offset : Nat) :
    readAmount content offset 0 = 0 ∧
    consumedPlaintext memory offset (readAmount content offset 0) = memory := by
  simp [readAmount, consumedPlaintext_zero]

theorem readPlaintext_preserves_clean (memory : PlainMemory) (loan content offset requested : Nat)
    (clean : CleanPlaintext memory loan content offset) :
    CleanPlaintext (consumedPlaintext memory offset (readAmount content offset requested))
      loan content (offset + readAmount content offset requested) := by
  obtain ⟨valid, fits, cleanPrefix, tail⟩ := clean
  have bounds := readAmount_bounds content offset requested valid
  refine ⟨bounds.2.2, fits, ?_, ?_⟩
  · intro i hi
    by_cases old : i < offset
    · rw [consumedPlaintext_outside memory offset _ i (Or.inl old)]
      exact cleanPrefix i old
    · exact consumedPlaintext_inside memory offset _ i (by omega) hi
  · intro i hi hj
    rw [consumedPlaintext_outside memory offset _ i (Or.inr (by omega))]
    exact tail i hi hj

theorem readPlaintext_complete_zero (memory : PlainMemory) (loan content offset : Nat)
    (clean : CleanPlaintext memory loan content offset) (complete : offset = content) :
    ∀ i, i < loan → memory i = 0 := by
  obtain ⟨_, _, cleanPrefix, tail⟩ := clean
  intro i hi
  by_cases before : i < offset
  · exact cleanPrefix i before
  · exact tail i (by omega) hi

/-- Repeating a full-loan wipe at completion changes no byte, even outside the loan. -/
theorem readPlaintext_final_wipe_redundant (memory : PlainMemory) (loan content offset : Nat)
    (clean : CleanPlaintext memory loan content offset) (complete : offset = content) :
    consumedPlaintext memory 0 loan = memory := by
  have zero := readPlaintext_complete_zero memory loan content offset clean complete
  funext i
  by_cases inside : i < loan
  · simp [consumedPlaintext, inside, zero i inside]
  · exact consumedPlaintext_outside memory 0 loan i (Or.inr (by omega))

/-- Arbitrarily many partial or zero-length reads; each step uses its preceding offset. -/
inductive PlainReads (content : Nat) : PlainMemory → Nat → PlainMemory → Nat → Prop where
  | refl (memory offset) : PlainReads content memory offset memory offset
  | step {initial first memory offset} (prior : PlainReads content initial first memory offset)
      (requested : Nat) :
      PlainReads content initial first
        (consumedPlaintext memory offset (readAmount content offset requested))
        (offset + readAmount content offset requested)

theorem plainReads_preserves_clean (loan content first last : Nat) (initial final : PlainMemory)
    (trace : PlainReads content initial first final last)
    (clean : CleanPlaintext initial loan content first) : CleanPlaintext final loan content last := by
  induction trace with
  | refl => exact clean
  | step prior requested ih => exact readPlaintext_preserves_clean _ _ _ _ requested ih

theorem plainReads_complete_zero (loan content first last : Nat) (initial final : PlainMemory)
    (trace : PlainReads content initial first final last)
    (clean : CleanPlaintext initial loan content first) (complete : last = content) :
    ∀ i, i < loan → final i = 0 := by
  exact readPlaintext_complete_zero final loan content last
    (plainReads_preserves_clean loan content first last initial final trace clean) complete

end Tls13
