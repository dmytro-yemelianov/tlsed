import TlsCore
import Tls13.Reassembly

open Aeneas Aeneas.Std Result

set_option autoImplicit false

namespace Tls13.Linked

/-- Aeneas usize is a platform unsigned integer with at least 32 bits. -/
theorem usize_has_u24_headroom : 16777219 ≤ Usize.max := by
  have width := Usize.bounds_eq
  norm_num [U32.max, U64.max, U32.numBits, U64.numBits, UScalarTy.numBits] at width
  omega

/-- Semantic relation for the actual Rust checked-add operation. -/
theorem checked_add_refines (left right : Usize) :
    (Usize.checked_add left right).map UScalar.val =
      if left.val + right.val ≤ Usize.max then some (left.val + right.val) else none := by
  have spec := Usize.checked_add_bv_spec left right
  cases eq : Usize.checked_add left right with
  | none => simp only [eq] at spec; simp [show ¬left.val + right.val ≤ Usize.max by omega]
  | some result =>
    simp only [eq] at spec
    simp [spec.1, spec.2.1]

/-- Actual translated handshake length arithmetic agrees for every representable input. -/
theorem handshake_total_refines (body cap : Usize) :
    ∃ result : Option Usize,
      tls_core.handshake.checked_handshake_total body cap = ok result ∧
      result.map UScalar.val = checkedHandshakeTotal body.val cap.val := by
  by_cases wire : body.val ≤ maxHandshakeBody
  · by_cases configured : body.val ≤ cap.val
    · have wireGuard : ¬body > tls_core.handshake.MAX_HANDSHAKE_BODY := by
        change ¬body.val > (tls_core.handshake.MAX_HANDSHAKE_BODY).val
        simpa [tls_core.handshake.MAX_HANDSHAKE_BODY, maxHandshakeBody] using Nat.not_lt.mpr wire
      have capGuard : ¬body > cap := Nat.not_lt.mpr configured
      refine ⟨Usize.checked_add body tls_core.handshake.HANDSHAKE_HEADER_LEN, ?_, ?_⟩
      · simp [tls_core.handshake.checked_handshake_total, wireGuard, capGuard]
      · rw [checked_add_refines]
        have fits : body.val + 4 ≤ Usize.max := by
          have := usize_has_u24_headroom
          simp only [maxHandshakeBody] at wire
          omega
        simp [tls_core.handshake.HANDSHAKE_HEADER_LEN, fits,
          checkedHandshakeTotal, wire, configured]
    · have capGuard : body > cap := Nat.lt_of_not_ge configured
      have wireGuard : ¬body > tls_core.handshake.MAX_HANDSHAKE_BODY := by
        change ¬body.val > (tls_core.handshake.MAX_HANDSHAKE_BODY).val
        simpa [tls_core.handshake.MAX_HANDSHAKE_BODY, maxHandshakeBody] using Nat.not_lt.mpr wire
      exact ⟨none, by simp [tls_core.handshake.checked_handshake_total, wireGuard, capGuard],
        by simp [checkedHandshakeTotal, configured]⟩
  · have wireGuard : body > tls_core.handshake.MAX_HANDSHAKE_BODY := by
      change body.val > (tls_core.handshake.MAX_HANDSHAKE_BODY).val
      simpa [tls_core.handshake.MAX_HANDSHAKE_BODY, maxHandshakeBody] using Nat.lt_of_not_ge wire
    exact ⟨none, by simp [tls_core.handshake.checked_handshake_total, wireGuard],
      by simp [checkedHandshakeTotal, wire]⟩

/-- A valid u24 body cannot fail checked addition and is bounded by both limits. -/
theorem handshake_total_success (body cap : Usize)
    (wire : body.val ≤ maxHandshakeBody) (configured : body.val ≤ cap.val) :
    ∃ result : Usize,
      tls_core.handshake.checked_handshake_total body cap = ok (some result) ∧
      result.val = body.val + 4 ∧ result.val ≤ cap.val + 4 ∧ result.val ≤ 16777219 := by
  obtain ⟨result, execution, agrees⟩ := handshake_total_refines body cap
  rw [handshakeTotal_accepts body.val cap.val wire configured] at agrees
  cases result with
  | none => simp at agrees
  | some result =>
    simp only [Option.map_some, Option.some.injEq] at agrees
    refine ⟨result, execution, agrees, ?_, ?_⟩
    · omega
    · simp only [maxHandshakeBody] at wire; omega

/-- Oversized lengths return None, not a successful message or arithmetic panic. -/
theorem handshake_total_rejects (body cap : Usize)
    (oversized : maxHandshakeBody < body.val ∨ cap.val < body.val) :
    tls_core.handshake.checked_handshake_total body cap = ok none := by
  obtain ⟨result, execution, agrees⟩ := handshake_total_refines body cap
  rw [handshakeTotal_rejects body.val cap.val oversized] at agrees
  cases result with
  | none => exact execution
  | some result => simp at agrees

end Tls13.Linked

#print axioms Tls13.Linked.usize_has_u24_headroom
#print axioms Tls13.Linked.checked_add_refines
#print axioms Tls13.Linked.handshake_total_refines
#print axioms Tls13.Linked.handshake_total_success
#print axioms Tls13.Linked.handshake_total_rejects
