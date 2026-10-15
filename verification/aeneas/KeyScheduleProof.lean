import ReassemblyProof
import Tls13.KeySchedule

open Aeneas Aeneas.Std Result

set_option autoImplicit false

namespace Tls13.Linked

/-- Actual translated HKDF label guard, including both native addition operations. -/
theorem hkdf_label_size_refines (output label context : Usize) :
    ∃ result : Option Usize,
      tls_core.key_schedule.hkdf_label_encoded_len output label context = ok result ∧
      result.map UScalar.val = hkdfLabelSize output.val label.val context.val := by
  by_cases valid : output.val ≤ 65535 ∧ 1 ≤ label.val ∧ label.val ≤ 249 ∧ context.val ≤ 255
  · have outputBound := valid.1
    have labelPositive := valid.2.1
    have labelBound := valid.2.2.1
    have contextBound := valid.2.2.2
    have labelNonzero : label ≠ 0#usize := by
      intro eq
      have value := congrArg UScalar.val eq
      simp at value
      omega
    have machineHeadroom := usize_has_u24_headroom
    have firstFits : (10#usize).val + label.val ≤ UScalar.max .Usize := by
      rw [UScalar.max_USize_eq]
      simp
      omega
    obtain ⟨withLabel, firstExecution, firstValue⟩ := WP.spec_imp_exists (UScalar.add_spec firstFits)
    have secondFits : withLabel.val + context.val ≤ UScalar.max .Usize := by
      rw [UScalar.max_USize_eq]
      simp at firstValue
      omega
    obtain ⟨size, secondExecution, secondValue⟩ := WP.spec_imp_exists (UScalar.add_spec secondFits)
    have exactSize : size.val = 10 + label.val + context.val := by
      simp at firstValue
      omega
    refine ⟨some size, ?_, ?_⟩
    · simp [tls_core.key_schedule.hkdf_label_encoded_len, Nat.not_lt.mpr outputBound,
        labelNonzero, Nat.not_lt.mpr labelBound, Nat.not_lt.mpr contextBound,
        firstExecution, secondExecution]
    · simp [hkdfLabelSize, valid, exactSize]
  · have invalid : 65535 < output.val ∨ label.val = 0 ∨ 249 < label.val ∨ 255 < context.val := by omega
    refine ⟨none, ?_, ?_⟩
    · rcases invalid with outputLarge | labelZero | labelLarge | contextLarge
      · simp [tls_core.key_schedule.hkdf_label_encoded_len, outputLarge]
      · have zero : label = 0#usize := by apply UScalar.eq_of_val_eq; simpa using labelZero
        simp [tls_core.key_schedule.hkdf_label_encoded_len, zero]
      · simp [tls_core.key_schedule.hkdf_label_encoded_len, labelLarge]
      · simp [tls_core.key_schedule.hkdf_label_encoded_len, contextLarge]
    · simp [hkdfLabelSize, valid]

/-- Accepted lengths always produce the exact mandatory size without arithmetic failure. -/
theorem hkdf_label_size_success (output label context : Usize)
    (valid : output.val ≤ 65535 ∧ 1 ≤ label.val ∧ label.val ≤ 249 ∧ context.val ≤ 255) :
    ∃ size : Usize,
      tls_core.key_schedule.hkdf_label_encoded_len output label context = ok (some size) ∧
      size.val = 10 + label.val + context.val ∧ size.val ≤ 514 := by
  obtain ⟨result, execution, agrees⟩ := hkdf_label_size_refines output label context
  rw [hkdfLabelSize, if_pos valid] at agrees
  cases result with
  | none => simp at agrees
  | some size =>
    simp only [Option.map_some, Option.some.injEq] at agrees
    exact ⟨size, execution, agrees, by omega⟩

theorem hkdf_label_size_rejects (output label context : Usize)
    (invalid : 65535 < output.val ∨ label.val = 0 ∨ 249 < label.val ∨ 255 < context.val) :
    tls_core.key_schedule.hkdf_label_encoded_len output label context = ok none := by
  obtain ⟨result, execution, agrees⟩ := hkdf_label_size_refines output label context
  rw [hkdfLabelSize_rejects output.val label.val context.val invalid] at agrees
  cases result with
  | none => exact execution
  | some size => simp at agrees

/-- The actual Rust helper returns the minimum required fixed-format byte footprint.
This theorem does not optimize CPU time, crypto cost, or alternate serialization formats. -/
theorem hkdf_label_size_minimal (output labelLength contextLength : Usize)
    (valid : output.val ≤ 65535 ∧ 1 ≤ labelLength.val ∧ labelLength.val ≤ 249 ∧ contextLength.val ≤ 255)
    (outputField labelLengthField labelPrefix label contextLengthField context : List Nat)
    (outputBytes : 2 ≤ outputField.length) (labelLengthBytes : 1 ≤ labelLengthField.length)
    (prefixBytes : 6 ≤ labelPrefix.length) (labelBytes : labelLength.val ≤ label.length)
    (contextLengthBytes : 1 ≤ contextLengthField.length) (contextBytes : contextLength.val ≤ context.length) :
    ∃ size : Usize,
      tls_core.key_schedule.hkdf_label_encoded_len output labelLength contextLength = ok (some size) ∧
      size.val ≤ (outputField ++ labelLengthField ++ labelPrefix ++ label ++ contextLengthField ++ context).length := by
  obtain ⟨size, execution, exactSize, _⟩ := hkdf_label_size_success output labelLength contextLength valid
  refine ⟨size, execution, ?_⟩
  rw [exactSize]
  exact hkdfLabel_footprint_minimal labelLength.val contextLength.val
    outputField labelLengthField labelPrefix label contextLengthField context
    outputBytes labelLengthBytes prefixBytes labelBytes contextLengthBytes contextBytes

end Tls13.Linked

#print axioms Tls13.Linked.hkdf_label_size_refines
#print axioms Tls13.Linked.hkdf_label_size_success
#print axioms Tls13.Linked.hkdf_label_size_rejects
#print axioms Tls13.Linked.hkdf_label_size_minimal
