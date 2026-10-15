import ReassemblyProof
import Tls13.Protected

open Aeneas Aeneas.Std Result

set_option autoImplicit false

namespace Tls13.Linked

theorem max_inner_plaintext_evaluates :
    tls_core.protected.MAX_INNER_PLAINTEXT = ok (16385#usize) := by
  have fits : (16384#usize).val + (1#usize).val ≤ UScalar.max .Usize := by
    rw [UScalar.max_USize_eq]
    have := usize_has_u24_headroom
    simp
    omega
  obtain ⟨result, execution, value⟩ := WP.spec_imp_exists (UScalar.add_spec fits)
  have eq : result = 16385#usize := by
    apply UScalar.eq_of_val_eq
    simpa using value
  simpa [tls_core.protected.MAX_INNER_PLAINTEXT, tls_core.wire.MAX_PLAINTEXT, eq] using execution

/-- The production protected-record helper agrees with the natural model,
including both checked-add overflow rejection paths. -/
theorem inner_length_refines (content padding limit : Usize) :
    ∃ result : Option Usize,
      tls_core.protected.inner_length content padding limit = ok result ∧
      result.map UScalar.val = checkedInnerLength content.val padding.val limit.val := by
  have headroom := usize_has_u24_headroom
  by_cases zero : limit = 0#usize
  · subst limit
    exact ⟨none, by simp [tls_core.protected.inner_length],
      by simp [checkedInnerLength]⟩
  · by_cases large : limit > 16385#usize
    · have largeValue : 16385 < limit.val := by simpa using large
      exact ⟨none, by simp [tls_core.protected.inner_length, zero, max_inner_plaintext_evaluates, largeValue],
        by simp [checkedInnerLength, show ¬limit.val ≤ 16385 by omega]⟩
    · have limitBound : limit.val ≤ 16385 := by simpa using Nat.not_lt.mp large
      have positive : 1 ≤ limit.val := by
        have : limit.val ≠ 0 := by
          intro eq
          apply zero
          apply UScalar.eq_of_val_eq
          simpa using eq
        omega
      have firstSpec := Usize.checked_add_bv_spec content (1#usize)
      cases first : Usize.checked_add content (1#usize) with
      | none =>
        simp only [first] at firstSpec
        have tooLarge : ¬content.val + 1 + padding.val ≤ limit.val := by
          simp at firstSpec
          omega
        exact ⟨none, by simp [tls_core.protected.inner_length, zero,
          max_inner_plaintext_evaluates, lift, first],
          by simp [checkedInnerLength, tooLarge]⟩
      | some withType =>
        simp only [first] at firstSpec
        have withTypeValue : withType.val = content.val + 1 := by simpa using firstSpec.2.1
        have secondSpec := Usize.checked_add_bv_spec withType padding
        cases second : Usize.checked_add withType padding with
        | none =>
          simp only [second] at secondSpec
          have tooLarge : ¬content.val + 1 + padding.val ≤ limit.val := by omega
          exact ⟨none, by simp [tls_core.protected.inner_length, zero,
            max_inner_plaintext_evaluates, lift, first, second],
            by simp [checkedInnerLength, tooLarge]⟩
        | some length =>
          simp only [second] at secondSpec
          have lengthValue : length.val = content.val + 1 + padding.val := by omega
          by_cases exceeds : length > limit
          · change limit.val < length.val at exceeds
            have tooLarge : ¬content.val + 1 + padding.val ≤ limit.val := by omega
            exact ⟨none, by simp [tls_core.protected.inner_length, zero,
              max_inner_plaintext_evaluates, lift, first, second, exceeds],
              by simp [checkedInnerLength, tooLarge]⟩
          · change ¬limit.val < length.val at exceeds
            have fits : content.val + 1 + padding.val ≤ limit.val := by omega
            exact ⟨some length, by simp [tls_core.protected.inner_length, zero,
              max_inner_plaintext_evaluates, Nat.not_lt.mpr limitBound, lift, first, second, exceeds],
              by simp [checkedInnerLength, positive, limitBound, fits, lengthValue]⟩

/-- Production protected content-type checks coincide with the modeled policy. -/
theorem valid_content_type_refines (kind : U8) (content : Usize) :
    tls_core.protected.valid_content_type kind content = ok (validInnerType kind.val content.val) := by
  have h21 : (21#8#uscalar : U8).val = 21 := rfl
  have h22 : (22#8#uscalar : U8).val = 22 := rfl
  have h23 : (23#8#uscalar : U8).val = 23 := rfl
  unfold tls_core.protected.valid_content_type
  split <;> simp_all [validInnerType, UScalar.eq_equiv, Nat.pos_iff_ne_zero]
  by_cases zero : content = 0#usize
  · simp [zero]
  · have valueNonzero : content.val ≠ 0 := by simpa using zero
    simp [zero, valueNonzero]

end Tls13.Linked

#print axioms Tls13.Linked.max_inner_plaintext_evaluates
#print axioms Tls13.Linked.inner_length_refines
#print axioms Tls13.Linked.valid_content_type_refines
