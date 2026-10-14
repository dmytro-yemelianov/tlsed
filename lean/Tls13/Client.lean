import Init

namespace Tls13

/-- Expected verified wire/internal event for phases zero through five. -/
def clientFlightMessage (phase : Nat) : Nat :=
  if phase = 0 then 2 else if phase = 1 then 8 else if phase = 2 then 11
  else if phase = 3 then 15 else if phase = 4 then 20 else 252

/-- Verification is supplied by the endpoint; the function does not perform crypto.
253 is validated HRR, 252 is client Finished handoff, 255 is fatal failure. -/
def clientPhaseNext (phase message : Nat) (verified retried : Bool) : Option Nat :=
  if message = 255 then some 7
  else if verified then
    if phase < 6 ∧ message = clientFlightMessage phase then some (phase + 1)
    else if phase = 0 ∧ message = 253 ∧ retried = false then some 0 else none
  else none

theorem clientFlightMessage_bounded (phase : Nat) : clientFlightMessage phase ≤ 252 := by
  by_cases h0 : phase = 0 <;> by_cases h1 : phase = 1 <;>
    by_cases h2 : phase = 2 <;> by_cases h3 : phase = 3 <;>
    by_cases h4 : phase = 4 <;> simp_all [clientFlightMessage]

theorem clientPhaseNext_exact (phase message next : Nat) (verified retried : Bool) :
    clientPhaseNext phase message verified retried = some next ↔
      (message = 255 ∧ next = 7) ∨
      (verified = true ∧ phase < 6 ∧ message = clientFlightMessage phase ∧ next = phase + 1) ∨
      (verified = true ∧ phase = 0 ∧ message = 253 ∧ retried = false ∧ next = 0) := by
  have bound := clientFlightMessage_bounded phase
  cases verified <;> cases retried <;>
    by_cases fatal : message = 255 <;>
    by_cases flight : phase < 6 ∧ message = clientFlightMessage phase <;>
    by_cases retry : phase = 0 ∧ message = 253 <;>
    simp_all [clientPhaseNext, clientFlightMessage] <;> try omega
  all_goals split <;> simp_all
  all_goals split <;> simp_all <;> omega

theorem client_unverified_rejected (phase message : Nat) (retried : Bool)
    (ordinary : message ≠ 255) : clientPhaseNext phase message false retried = none := by
  simp [clientPhaseNext, ordinary]

theorem client_failed_terminal (message next : Nat) (verified retried : Bool)
    (accepted : clientPhaseNext 7 message verified retried = some next) : next = 7 := by
  have shape := (clientPhaseNext_exact 7 message next verified retried).mp accepted
  omega

theorem client_successor_bounded (phase message next : Nat) (verified retried : Bool)
    (accepted : clientPhaseNext phase message verified retried = some next) : next ≤ 7 := by
  have shape := (clientPhaseNext_exact phase message next verified retried).mp accepted
  omega

theorem client_established_no_handshake (message : Nat) (verified retried : Bool)
    (ordinary : message ≠ 255) : clientPhaseNext 6 message verified retried = none := by
  simp [clientPhaseNext, ordinary]

structure ClientPolicyEvent where
  message : Nat
  verified : Bool
  deriving DecidableEq, Repr

structure ClientPolicyState where
  phase : Nat := 0
  retried : Bool := false
  deriving DecidableEq, Repr

/-- Atomic bookkeeping required around the pure Rust phase guard. -/
def clientPolicyStep (state : ClientPolicyState) (event : ClientPolicyEvent) : Option ClientPolicyState := do
  let next ← clientPhaseNext state.phase event.message event.verified state.retried
  some ⟨next, state.retried || event.message == 253⟩

/-- The endpoint must turn rejection into failure; rejection is not authentication. -/
def clientPolicyApply (state : ClientPolicyState) (event : ClientPolicyEvent) : ClientPolicyState :=
  (clientPolicyStep state event).getD ⟨7, state.retried⟩

theorem client_step_projects (state next : ClientPolicyState) (event : ClientPolicyEvent)
    (accepted : clientPolicyStep state event = some next) :
    clientPhaseNext state.phase event.message event.verified state.retried = some next.phase ∧
      next.retried = (state.retried || event.message == 253) := by
  unfold clientPolicyStep at accepted
  cases outcome : clientPhaseNext state.phase event.message event.verified state.retried <;>
    simp [outcome] at accepted
  cases accepted
  simp

theorem client_illegal_enters_failed (state : ClientPolicyState) (event : ClientPolicyEvent)
    (rejected : clientPolicyStep state event = none) :
    (clientPolicyApply state event).phase = 7 := by simp [clientPolicyApply, rejected]

theorem client_apply_failure_terminal (state : ClientPolicyState) (event : ClientPolicyEvent)
    (failed : state.phase = 7) : (clientPolicyApply state event).phase = 7 := by
  cases outcome : clientPolicyStep state event with
  | none => exact client_illegal_enters_failed state event outcome
  | some next =>
    have phase := (client_step_projects state next event outcome).1
    rw [failed] at phase
    simpa [clientPolicyApply, outcome] using
      client_failed_terminal event.message next.phase event.verified state.retried phase

theorem client_hrr_bookkeeping (state next : ClientPolicyState)
    (accepted : clientPolicyStep state ⟨253, true⟩ = some next) :
    state.phase = 0 ∧ state.retried = false ∧ next.phase = 0 ∧ next.retried = true := by
  obtain ⟨phase, retry⟩ := client_step_projects state next ⟨253, true⟩ accepted
  have shape := (clientPhaseNext_exact state.phase 253 next.phase true state.retried).mp phase
  have bound := clientFlightMessage_bounded state.phase
  simp at shape retry
  have oldRetry : state.retried = false := by
    rcases shape with flight | hrr
    · omega
    · exact hrr.2.1
  exact ⟨by omega, oldRetry, by omega, retry⟩

theorem client_duplicate_hrr_rejected (phase : Nat) (verified : Bool) :
    clientPhaseNext phase 253 verified true = none := by
  have bound := clientFlightMessage_bounded phase
  have mismatch : 253 ≠ clientFlightMessage phase := by omega
  simp [clientPhaseNext, mismatch]

inductive ClientPolicyTrace : ClientPolicyState → List ClientPolicyEvent → Prop
  | start : ClientPolicyTrace ⟨0, false⟩ []
  | step {state next history event} : ClientPolicyTrace state history →
      clientPolicyStep state event = some next → ClientPolicyTrace next (history ++ [event])

/-- Each completed flight has a verified event in the accepted trace. -/
theorem client_trace_evidence {state history : _} (trace : ClientPolicyTrace state history) :
    state.phase ≤ 6 → ∀ stage, 1 ≤ stage → stage ≤ state.phase →
      (⟨clientFlightMessage (stage - 1), true⟩ : ClientPolicyEvent) ∈ history := by
  induction trace with
  | start => intro _ stage positive zero; simp at zero; omega
  | @step state next history event trace accepted ih =>
    intro bound stage positive earlier
    obtain ⟨phase, _⟩ := client_step_projects state next event accepted
    have shape := (clientPhaseNext_exact state.phase event.message next.phase event.verified state.retried).mp phase
    rcases shape with fatal | flight | retry
    · omega
    · obtain ⟨verified, oldBound, message, newPhase⟩ := flight
      simp only [List.mem_append, List.mem_singleton]
      by_cases before : stage ≤ state.phase
      · exact Or.inl (ih (by omega) stage positive before)
      · right
        have previous : stage - 1 = state.phase := by omega
        cases event
        simp_all
    · omega

theorem client_established_requires_verified_flights {state history : _}
    (trace : ClientPolicyTrace state history) (established : state.phase = 6) :
    (⟨11, true⟩ : ClientPolicyEvent) ∈ history ∧
    (⟨15, true⟩ : ClientPolicyEvent) ∈ history ∧
    (⟨20, true⟩ : ClientPolicyEvent) ∈ history ∧
    (⟨252, true⟩ : ClientPolicyEvent) ∈ history := by
  have evidence := client_trace_evidence trace (by omega)
  exact ⟨evidence 3 (by decide) (by omega), evidence 4 (by decide) (by omega),
    evidence 5 (by decide) (by omega), evidence 6 (by decide) (by omega)⟩

theorem client_trace_retry_count {state history : _} (trace : ClientPolicyTrace state history) :
    (history.filter (fun event => event.message == 253)).length = if state.retried then 1 else 0 := by
  induction trace with
  | start => rfl
  | @step state next history event trace accepted ih =>
    obtain ⟨phase, retry⟩ := client_step_projects state next event accepted
    by_cases hrr : event.message = 253
    · have shape := (clientPhaseNext_exact state.phase event.message next.phase event.verified state.retried).mp phase
      have bound := clientFlightMessage_bounded state.phase
      have old : state.retried = false := by rcases shape with fatal | flight | retry <;> simp_all <;> omega
      simp [List.filter_append, hrr, retry, old] at ih ⊢
      exact ih
    · simp [List.filter_append, hrr, retry, ih]

theorem client_trace_at_most_one_hrr {state history : _} (trace : ClientPolicyTrace state history) :
    (history.filter (fun event => event.message == 253)).length ≤ 1 := by
  rw [client_trace_retry_count trace]
  split <;> omega

def clientReleaseAllowed (state : ClientPolicyState) (aeadOk : Bool) : Bool :=
  state.phase == 6 && aeadOk

theorem client_release_requires_established (state : ClientPolicyState) (aeadOk : Bool)
    (released : clientReleaseAllowed state aeadOk = true) : state.phase = 6 ∧ aeadOk = true := by
  simpa [clientReleaseAllowed] using released

theorem client_release_requires_verified_flights {state history : _}
    (trace : ClientPolicyTrace state history) (aeadOk : Bool)
    (released : clientReleaseAllowed state aeadOk = true) :
    (⟨11, true⟩ : ClientPolicyEvent) ∈ history ∧
    (⟨15, true⟩ : ClientPolicyEvent) ∈ history ∧
    (⟨20, true⟩ : ClientPolicyEvent) ∈ history ∧
    (⟨252, true⟩ : ClientPolicyEvent) ∈ history := by
  exact client_established_requires_verified_flights trace
    (client_release_requires_established state aeadOk released).1

end Tls13
