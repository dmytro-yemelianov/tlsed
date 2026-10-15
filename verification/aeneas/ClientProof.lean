import TlsCore
import Tls13.Client

open Aeneas Aeneas.Std Result

set_option autoImplicit false
set_option maxHeartbeats 2000000

namespace Tls13.Linked

/-- The actual Rust byte guard is total and agrees with the natural policy. -/
theorem client_phase_refines (phase message : U8) (verified retried : Bool) :
    ∃ result : Option U8,
      tls_core.client_policy.client_phase_next phase message verified retried = ok result ∧
      result.map UScalar.val = clientPhaseNext phase.val message.val verified retried := by
  by_cases fatal : message = (255#u8 : U8)
  · refine ⟨some (7#u8), ?_, ?_⟩ <;>
      simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, UScalar.eq_equiv]
  · cases verified with
    | false =>
      refine ⟨none, ?_, ?_⟩ <;>
        simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, UScalar.eq_equiv]
    | true =>
      by_cases phase0 : phase = (0#u8 : U8)
      · subst phase
        by_cases expected : message = (2#u8 : U8)
        · refine ⟨some (1#u8), ?_, ?_⟩ <;>
            simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
        · by_cases hrr : message = (253#u8 : U8)
          · cases retried with
            | false =>
              refine ⟨some (0#u8), ?_, ?_⟩ <;>
                simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
            | true =>
              refine ⟨none, ?_, ?_⟩ <;>
                simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
          · refine ⟨none, ?_, ?_⟩ <;>
              simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
      · by_cases phase1 : phase = (1#u8 : U8)
        · subst phase
          by_cases expected : message = (8#u8 : U8)
          · refine ⟨some (2#u8), ?_, ?_⟩ <;>
              simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
          · refine ⟨none, ?_, ?_⟩ <;>
              simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
        · by_cases phase2 : phase = (2#u8 : U8)
          · subst phase
            by_cases expected : message = (11#u8 : U8)
            · refine ⟨some (3#u8), ?_, ?_⟩ <;>
                simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
            · refine ⟨none, ?_, ?_⟩ <;>
                simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
          · by_cases phase3 : phase = (3#u8 : U8)
            · subst phase
              by_cases expected : message = (15#u8 : U8)
              · refine ⟨some (4#u8), ?_, ?_⟩ <;>
                  simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
              · refine ⟨none, ?_, ?_⟩ <;>
                  simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
            · by_cases phase4 : phase = (4#u8 : U8)
              · subst phase
                by_cases expected : message = (20#u8 : U8)
                · refine ⟨some (5#u8), ?_, ?_⟩ <;>
                    simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
                · refine ⟨none, ?_, ?_⟩ <;>
                    simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
              · by_cases phase5 : phase = (5#u8 : U8)
                · subst phase
                  by_cases expected : message = (252#u8 : U8)
                  · refine ⟨some (6#u8), ?_, ?_⟩ <;>
                      simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
                  · refine ⟨none, ?_, ?_⟩ <;>
                      simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]
                · have high : 6 ≤ phase.val := by
                    simp only [UScalar.eq_equiv] at *
                    simp at *
                    omega
                  refine ⟨none, ?_, ?_⟩ <;>
                    simp_all [tls_core.client_policy.client_phase_next, clientPhaseNext, clientFlightMessage, UScalar.eq_equiv]

/-- Accepted translated executions are exactly the allowed verified transitions. -/
theorem client_phase_accepts_exact (phase message next : U8) (verified retried : Bool) :
    tls_core.client_policy.client_phase_next phase message verified retried = ok (some next) ↔
      (message.val = 255 ∧ next.val = 7) ∨
      (verified = true ∧ phase.val < 6 ∧ message.val = clientFlightMessage phase.val ∧ next.val = phase.val + 1) ∨
      (verified = true ∧ phase.val = 0 ∧ message.val = 253 ∧ retried = false ∧ next.val = 0) := by
  obtain ⟨result, execution, agrees⟩ := client_phase_refines phase message verified retried
  have equivalent :
      tls_core.client_policy.client_phase_next phase message verified retried = ok (some next) ↔
      clientPhaseNext phase.val message.val verified retried = some next.val := by
    rw [execution, ← agrees]
    cases result <;> simp [UScalar.eq_equiv]
  exact equivalent.trans (clientPhaseNext_exact phase.val message.val next.val verified retried)

theorem client_phase_unverified_rejects (phase message : U8) (retried : Bool)
    (ordinary : message ≠ (255#u8 : U8)) :
    tls_core.client_policy.client_phase_next phase message false retried = ok none := by
  obtain ⟨result, execution, agrees⟩ := client_phase_refines phase message false retried
  have value : message.val ≠ 255 := by simpa [UScalar.eq_equiv] using ordinary
  rw [client_unverified_rejected phase.val message.val retried value] at agrees
  cases result with
  | none => exact execution
  | some next => simp at agrees

theorem client_phase_failed_terminal (message next : U8) (verified retried : Bool)
    (accepted : tls_core.client_policy.client_phase_next (7#u8) message verified retried = ok (some next)) :
    next = (7#u8 : U8) := by
  have shape := (client_phase_accepts_exact (7#u8) message next verified retried).mp accepted
  apply UScalar.eq_of_val_eq
  simp at shape ⊢
  omega

theorem client_phase_duplicate_hrr_rejects (phase : U8) (verified : Bool) :
    tls_core.client_policy.client_phase_next phase (253#u8) verified true = ok none := by
  obtain ⟨result, execution, agrees⟩ := client_phase_refines phase (253#u8) verified true
  have rejected := client_duplicate_hrr_rejected phase.val verified
  simp only [show (253#u8 : U8).val = 253 by rfl, rejected] at agrees
  cases result with
  | none => exact execution
  | some next => simp at agrees

end Tls13.Linked

#print axioms Tls13.Linked.client_phase_refines
#print axioms Tls13.Linked.client_phase_accepts_exact
#print axioms Tls13.Linked.client_phase_unverified_rejects
#print axioms Tls13.Linked.client_phase_failed_terminal
#print axioms Tls13.Linked.client_phase_duplicate_hrr_rejects
