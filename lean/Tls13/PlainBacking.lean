import Tls13.Zeroization

namespace Tls13

def WholePlainClean (memory : PlainMemory) (loan : Nat) : Prop :=
  ∀ i, i < loan → memory i = 0

/-- Footprint obligation for an operation receiving only the active prefix.
This is a hypothesis about actual provider/slice behavior, not a crypto proof. -/
def WritesActivePrefix (before after : PlainMemory) (active : Nat) : Prop :=
  ∀ i, active ≤ i → after i = before i

/-- Functional interpretation of replacing a prefix while retaining its backing. -/
def replacePlainPrefix (before prefixBytes : PlainMemory) (active : Nat) : PlainMemory :=
  fun i => if i < active then prefixBytes i else before i

theorem replacePlainPrefix_inside (before prefixBytes : PlainMemory) (active i : Nat)
    (inside : i < active) : replacePlainPrefix before prefixBytes active i = prefixBytes i := by
  simp [replacePlainPrefix, inside]

theorem replacePlainPrefix_footprint (before prefixBytes : PlainMemory) (active : Nat) :
    WritesActivePrefix before (replacePlainPrefix before prefixBytes active) active := by
  intro i outside
  simp [replacePlainPrefix, show ¬ i < active by omega]

theorem activeOpen_preserves_backing (before after : PlainMemory) (loan active : Nat)
    (clean : WholePlainClean before loan) (footprint : WritesActivePrefix before after active) :
    ∀ i, active ≤ i → i < loan → after i = 0 := by
  intro i outside inside
  rw [footprint i outside]
  exact clean i inside

/-- Recombine the tail cleared by opening with the untouched, already-clean backing. -/
theorem activeOpen_tail_recombined (before after : PlainMemory) (loan content active : Nat)
    (clean : WholePlainClean before loan) (footprint : WritesActivePrefix before after active)
    (openedTail : ∀ i, content ≤ i → i < active → after i = 0) :
    ∀ i, content ≤ i → i < loan → after i = 0 := by
  intro i lower upper
  by_cases inside : i < active
  · exact openedTail i lower inside
  · exact activeOpen_preserves_backing before after loan active clean footprint i (by omega) upper

theorem activeOpen_clean (before after : PlainMemory) (loan content active : Nat)
    (contentFits : content ≤ active) (activeFits : active ≤ loan)
    (clean : WholePlainClean before loan) (footprint : WritesActivePrefix before after active)
    (openedTail : ∀ i, content ≤ i → i < active → after i = 0) :
    CleanPlaintext after loan content 0 := by
  refine ⟨by omega, by omega, ?_, ?_⟩
  · intro i hi
    omega
  · exact activeOpen_tail_recombined before after loan content active clean footprint openedTail

/-- The existing successful-open model applied only to the prefix satisfies the obligations. -/
theorem replaceOpenedPrefix_clean (before arbitrary : PlainMemory) (loan content active : Nat)
    (contentFits : content ≤ active) (activeFits : active ≤ loan)
    (clean : WholePlainClean before loan) :
    CleanPlaintext
      (replacePlainPrefix before (openedPlaintext arbitrary active content) active) loan content 0 := by
  apply activeOpen_clean before _ loan content active contentFits activeFits clean
  · exact replacePlainPrefix_footprint before _ active
  · intro i lower upper
    rw [replacePlainPrefix_inside before _ active i upper]
    exact openedPlaintext_tail arbitrary active content i lower upper

theorem activeOpen_complete_reads_clean (before opened final : PlainMemory)
    (loan content active : Nat) (contentFits : content ≤ active) (activeFits : active ≤ loan)
    (clean : WholePlainClean before loan) (footprint : WritesActivePrefix before opened active)
    (openedTail : ∀ i, content ≤ i → i < active → opened i = 0)
    (reads : PlainReads content opened 0 final content) : WholePlainClean final loan := by
  exact plainReads_complete_zero loan content 0 content opened final reads
    (activeOpen_clean before opened loan content active contentFits activeFits clean footprint openedTail) rfl

theorem fullClear_backing_clean (memory : PlainMemory) (loan : Nat) :
    WholePlainClean (consumedPlaintext memory 0 loan) loan := by
  intro i inside
  exact consumedPlaintext_inside memory 0 loan i (by omega) (by omega)

theorem identity_backing_clean (before after : PlainMemory) (loan : Nat)
    (clean : WholePlainClean before loan) (unchanged : after = before) : WholePlainClean after loan := by
  subst after
  exact clean

/-- Completed application records, full control-message clears, and untouched CCS.
An incomplete application read is deliberately not a boundary for a new record. -/
inductive PlainBackingAction (loan : Nat) : PlainMemory → PlainMemory → Prop where
  | record {before opened final content active}
      (contentFits : content ≤ active) (activeFits : active ≤ loan)
      (footprint : WritesActivePrefix before opened active)
      (openedTail : ∀ i, content ≤ i → i < active → opened i = 0)
      (reads : PlainReads content opened 0 final content) : PlainBackingAction loan before final
  | clear (before) : PlainBackingAction loan before (consumedPlaintext before 0 loan)
  | unchanged (memory) : PlainBackingAction loan memory memory

theorem plainBackingAction_clean (loan : Nat) (before after : PlainMemory)
    (action : PlainBackingAction loan before after) (clean : WholePlainClean before loan) :
    WholePlainClean after loan := by
  cases action with
  | record contentFits activeFits footprint openedTail reads =>
    exact activeOpen_complete_reads_clean _ _ _ _ _ _ contentFits activeFits clean footprint openedTail reads
  | clear => exact fullClear_backing_clean _ _
  | unchanged => exact clean

inductive PlainBackingCycles (loan : Nat) : PlainMemory → PlainMemory → Prop where
  | refl (memory) : PlainBackingCycles loan memory memory
  | step {initial before after} (prior : PlainBackingCycles loan initial before)
      (action : PlainBackingAction loan before after) : PlainBackingCycles loan initial after

theorem plainBackingCycles_clean (loan : Nat) (initial final : PlainMemory)
    (cycles : PlainBackingCycles loan initial final) (clean : WholePlainClean initial loan) :
    WholePlainClean final loan := by
  induction cycles with
  | refl => exact clean
  | step prior action ih => exact plainBackingAction_clean _ _ _ action ih

end Tls13
