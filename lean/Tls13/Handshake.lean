import Init

namespace Tls13

/-- States: start=0, hello=1, identity=2, signature=3, established=4, failed=5.
Events: hello=0, chain-and-identity verified=1, signature verified=2,
Finished verified=3, abort=4, AEAD failure=5. Events represent trusted evidence. -/
def authStep (state event : Nat) : Option Nat :=
  if state ≤ 5 ∧ event ≤ 5 then
    if event = 4 ∨ event = 5 then some 5
    else if state = event then some (state + 1) else none
  else none

def releaseAllowed (state : Nat) (aeadOk : Bool) : Bool := state == 4 && aeadOk

theorem authStep_characterization (state event next : Nat)
    (ok : authStep state event = some next) :
    (next = 5 ∧ (event = 4 ∨ event = 5)) ∨
      (state = event ∧ event < 4 ∧ next = state + 1) := by
  unfold authStep at ok
  split at ok <;> simp_all
  split at ok <;> simp_all <;> omega

theorem unexpected_event_rejected (state event : Nat)
    (valid : state ≤ 5 ∧ event < 4) (unexpected : state ≠ event) :
    authStep state event = none := by
  simp [authStep, valid.1, show event ≤ 5 by omega,
    show event ≠ 4 by omega, show event ≠ 5 by omega, unexpected]

theorem failure_is_terminal (event next : Nat)
    (ok : authStep 5 event = some next) : next = 5 := by
  have := authStep_characterization 5 event next ok
  omega

inductive AuthTrace : Nat → List Nat → Prop
  | start : AuthTrace 0 []
  | step {state next history event} : AuthTrace state history →
      authStep state event = some next → AuthTrace next (history ++ [event])

/-- Every completed authentication stage has its evidence event in the trace. -/
theorem authTrace_evidence {state history : _} (trace : AuthTrace state history) :
    state ≤ 4 → ∀ event < state, event ∈ history := by
  induction trace with
  | start => simp
  | @step state next history event trace ok ih =>
    intro bound required earlier
    have shape := authStep_characterization state event next ok
    rcases shape with bad | good
    · omega
    · have prevBound : state ≤ 4 := by omega
      have prior := ih prevBound
      simp only [List.mem_append, List.mem_singleton]
      by_cases h : required < state
      · exact Or.inl (prior required h)
      · right; omega

/-- Establishment requires chain+identity, CertificateVerify, and Finished events. -/
theorem established_requires_authentication {history : List Nat}
    (trace : AuthTrace 4 history) : 1 ∈ history ∧ 2 ∈ history ∧ 3 ∈ history := by
  have evidence := authTrace_evidence trace (by decide)
  exact ⟨evidence 1 (by decide), evidence 2 (by decide), evidence 3 (by decide)⟩

theorem aead_failure_blocks_release (state : Nat) :
    releaseAllowed state false = false := by simp [releaseAllowed]

theorem release_requires_established (state : Nat) (aead : Bool)
    (ok : releaseAllowed state aead = true) : state = 4 ∧ aead = true := by
  simpa [releaseAllowed] using ok

theorem release_requires_authentication {state history : _}
    (trace : AuthTrace state history) (aead : Bool)
    (ok : releaseAllowed state aead = true) :
    1 ∈ history ∧ 2 ∈ history ∧ 3 ∈ history ∧ aead = true := by
  obtain ⟨rfl, aeadOk⟩ := release_requires_established state aead ok
  obtain ⟨chainIdentity, signature, finished⟩ := established_requires_authentication trace
  exact ⟨chainIdentity, signature, finished, aeadOk⟩

end Tls13
