import TlsCore
import Tls13.Segmentation

open Aeneas Aeneas.Std Result

set_option autoImplicit false

namespace Tls13.Linked

/-- The actual Aeneas translation rejects zero capacity without panicking. -/
theorem record_count_zero (bytes : Usize) :
    tls_core.schedule.record_count bytes (0#usize) =
      ok (core.result.Result.Err tls_core.Error.InvalidLimit) := by
  simp [tls_core.schedule.record_count]

/-- The actual translated checked machine arithmetic succeeds and equals the
standalone mathematical count, for every representable positive capacity. -/
theorem record_count_refines (bytes capacity : Usize) (positive : 0 < capacity.val) :
    ∃ result : Usize,
      tls_core.schedule.record_count bytes capacity = ok (core.result.Result.Ok result) ∧
      result.val = recordCount bytes.val capacity.val := by
  have nonzero : capacity.val ≠ 0 := by omega
  have capne : capacity ≠ 0#usize := by
    intro h
    have hval := congrArg UScalar.val h
    simp at hval
    omega
  obtain ⟨quotient, hquotient, quotientValue⟩ := UScalar.div_spec bytes nonzero
  obtain ⟨remainder, hremainder, remainderValue⟩ :=
    WP.spec_imp_exists (UScalar.rem_spec bytes nonzero)
  let extra := core.convert.num.FromUsizeBool.from (remainder != 0#usize)
  have extraValue : extra.val = if bytes.val % capacity.val = 0 then 0 else 1 := by
    dsimp [extra, core.convert.num.FromUsizeBool.from]
    by_cases h : bytes.val % capacity.val = 0
    · have remzero : remainder = 0#usize := by
        apply UScalar.eq_of_val_eq
        simp [remainderValue, h]
      simp [remzero, h]
    · have remne : remainder ≠ 0#usize := by
        intro eq
        have hval := congrArg UScalar.val eq
        simp [remainderValue] at hval
        exact h hval
      simp [remne, h]
  have sumValue : quotient.val + extra.val = recordCount bytes.val capacity.val := by
    simp [recordCount, quotientValue, extraValue]
  have fits : quotient.val + extra.val ≤ UScalar.max .Usize := by
    rw [sumValue]
    have bound := recordCount_le_input bytes.val capacity.val positive
    have machineBound := bytes.hBounds
    simp only [UScalar.max]
    omega
  obtain ⟨result, hresult, resultValue⟩ :=
    WP.spec_imp_exists (UScalar.add_spec fits)
  have finalAdd : quotient + core.convert.num.FromUsizeBool.from (remainder != 0#usize) =
      ok result := hresult
  refine ⟨result, ?_, ?_⟩
  · simp [tls_core.schedule.record_count, capne, hquotient, hremainder, lift, finalAdd]
  · exact resultValue.trans sumValue

/-- The translated production Rust result is a feasible minimum over all
finite partitions respecting one positive fixed payload capacity. -/
theorem record_count_optimal (bytes capacity : Usize) (positive : 0 < capacity.val) :
    ∃ result : Usize,
      tls_core.schedule.record_count bytes capacity = ok (core.result.Result.Ok result) ∧
      bytes.val ≤ result.val * capacity.val ∧
      (∀ parts : List Nat, parts.sum = bytes.val →
        (∀ x ∈ parts, x ≤ capacity.val) → result.val ≤ parts.length) := by
  obtain ⟨result, execution, agrees⟩ := record_count_refines bytes capacity positive
  refine ⟨result, execution, ?_, ?_⟩
  · rw [agrees]
    exact recordCount_feasible bytes.val capacity.val positive
  · intro parts payload bounded
    rw [agrees]
    exact recordCount_partition_optimal bytes.val capacity.val positive parts payload bounded

/-- The same translated result minimizes the declared fixed framing-overhead cost. -/
theorem record_count_cost_optimal (bytes capacity : Usize) (positive : 0 < capacity.val)
    (overhead : Nat) :
    ∃ result : Usize,
      tls_core.schedule.record_count bytes capacity = ok (core.result.Result.Ok result) ∧
      (∀ parts : List Nat, parts.sum = bytes.val →
        (∀ x ∈ parts, x ≤ capacity.val) →
        bytes.val + overhead * result.val ≤ bytes.val + overhead * parts.length) := by
  obtain ⟨result, execution, agrees⟩ := record_count_refines bytes capacity positive
  refine ⟨result, execution, ?_⟩
  intro parts payload bounded
  rw [agrees]
  exact fixed_overhead_optimal bytes.val capacity.val overhead positive parts payload bounded

end Tls13.Linked

#print axioms Tls13.Linked.record_count_zero
#print axioms Tls13.Linked.record_count_refines
#print axioms Tls13.Linked.record_count_optimal
#print axioms Tls13.Linked.record_count_cost_optimal
