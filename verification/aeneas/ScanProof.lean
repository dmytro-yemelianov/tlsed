import TlsCore

open Aeneas Aeneas.Std Result

set_option autoImplicit false

namespace Tls13.Scan

/-- Byte `j` of a slice as a natural number. Reads past the end give the default `0`,
and every statement below only reads indices it has checked. -/
def byteAt (bytes : Slice Std.U8) (j : Nat) : Nat :=
  (bytes.val[j]!).val

/-- `i` is the largest index below `bound` holding a nonzero byte, or `none` when every
byte below `bound` is zero. This is `iter().rposition(|&b| b != 0)` on the prefix
`bytes[..bound]`. The definition determines the result, so a function satisfying it
computes `rposition`. -/
def IsLastNonzeroBelow (bytes : Slice Std.U8) (bound : Nat) : Option Std.Usize → Prop
  | none => ∀ j, j < bound → byteAt bytes j = 0
  | some i => i.val < bound ∧ byteAt bytes i.val ≠ 0 ∧
      ∀ j, i.val < j → j < bound → byteAt bytes j = 0

theorem scan_block_eq : tls_core.protected.SCAN_BLOCK = 64#usize := by
  unfold tls_core.protected.SCAN_BLOCK
  rfl

theorem U8.val_eq_zero_iff (x : Std.U8) : x.val = 0 ↔ x = 0#u8 := by
  constructor
  · intro h
    apply UScalar.eq_of_val_eq
    exact h
  · intro h
    subst h
    rfl

theorem U8.or_eq_zero_iff' (a b : Std.U8) : a ||| b = 0#u8 ↔ a = 0#u8 ∧ b = 0#u8 := by
  bv_tac 8

theorem U8.or_val_eq_zero_iff (a b : Std.U8) : (a ||| b).val = 0 ↔ a.val = 0 ∧ b.val = 0 := by
  rw [U8.val_eq_zero_iff, U8.val_eq_zero_iff, U8.val_eq_zero_iff, U8.or_eq_zero_iff']

theorem forall_lt_succ_iff (P : Nat → Prop) (n : Nat) :
    (∀ j, j < n + 1 → P j) ↔ (∀ j, j < n → P j) ∧ P n := by
  constructor
  · intro h
    exact ⟨fun j hj => h j (Nat.lt_succ_of_lt hj), h n (Nat.lt_succ_self n)⟩
  · rintro ⟨h1, h2⟩ j hj
    by_cases hjn : j = n
    · subst hjn
      exact h2
    · exact h1 j (Nat.lt_of_le_of_ne (Nat.le_of_lt_succ hj) hjn)

/-- A 64-byte window of `bytes` starting at `s`, read through `byteAt` of its sub-slice,
is the same window read from `bytes`. -/
theorem byteAt_slice (block bytes : Slice Std.U8) (s : Nat)
    (hb : block.val = bytes.val.slice s (s + 64)) (hs : s + 64 ≤ bytes.length) (j : Nat)
    (hj : j < 64) : byteAt block j = byteAt bytes (s + j) := by
  unfold byteAt
  rw [hb, List.getElem!_slice s (s + 64) j bytes.val ⟨hs, by agrind⟩]

theorem forall_window_iff (bytes : Slice Std.U8) (s : Nat) :
    (∀ j, j < 64 → byteAt bytes (s + j) = 0) ↔
      ∀ j, s ≤ j → j < s + 64 → byteAt bytes j = 0 := by
  constructor
  · intro h j h1 h2
    have := h (j - s) (by agrind)
    have e : s + (j - s) = j := by agrind
    rw [e] at this
    exact this
  · intro h j hj
    exact h (s + j) (by agrind) (by agrind)

/-- OR-accumulating the 64 bytes of `block` from index `i` reaches zero exactly when
the bytes before `i` and the byte at `i` are zero. -/
theorem block_is_zero_loop_spec (block : Slice Std.U8) (acc : Std.U8) (i : Std.Usize)
    (hlen : block.length = 64) (hi : i.val ≤ 64)
    (hacc : acc.val = 0 ↔ ∀ j, j < i.val → byteAt block j = 0) :
    tls_core.protected.block_is_zero_loop block acc i ⦃ r =>
      r.val = 0 ↔ ∀ j, j < 64 → byteAt block j = 0 ⦄ := by
  unfold tls_core.protected.block_is_zero_loop
  apply Aeneas.Std.loop.spec_decr_nat (fun s => 64 - s.2.val)
    (fun s => s.2.val ≤ 64 ∧ (s.1.val = 0 ↔ ∀ j, j < s.2.val → byteAt block j = 0))
    _ _ _ _ ⟨hi, hacc⟩
  rintro ⟨acc', i'⟩ ⟨hi', hacc'⟩
  dsimp only at hi' hacc' ⊢
  unfold tls_core.protected.block_is_zero_loop.body
  rw [scan_block_eq]
  split
  · step*
    · have hb : byteAt block i'.val = i1.val := by
        have hlt : i'.val < block.val.length := by agrind
        simp [byteAt, i1_post, List.getElem?_eq_getElem hlt]
      have hsucc : i2.val = i'.val + 1 := by agrind
      have hacc1 : acc1.val = 0 ↔ acc'.val = 0 ∧ i1.val = 0 := by
        rw [acc1_post, U8.or_val_eq_zero_iff]
      have key : (∀ j, j < i2.val → byteAt block j = 0) ↔
          (∀ j, j < i'.val → byteAt block j = 0) ∧ byteAt block i'.val = 0 := by
        rw [hsucc]
        exact forall_lt_succ_iff (fun j => byteAt block j = 0) i'.val
      refine ⟨by agrind, ?_, by agrind⟩
      rw [key, hacc1, hacc', hb]
  · have hi64 : i'.val = 64 := by agrind
    rw [hi64] at hacc'
    simp only [WP.spec_ok]
    exact hacc'

theorem block_is_zero_spec (bytes : Slice Std.U8) (start : Std.Usize)
    (hbound : start.val + 64 ≤ bytes.length) :
    tls_core.protected.block_is_zero bytes start ⦃ b =>
      b = true ↔ ∀ j, start.val ≤ j → j < start.val + 64 → byteAt bytes j = 0 ⦄ := by
  have hmax := Slice.length_ineq bytes
  unfold tls_core.protected.block_is_zero
  rw [scan_block_eq]
  step*
  have hb : block.val = bytes.val.slice start.val (start.val + 64) := by
    rw [block_post, i_post]
  step with block_is_zero_loop_spec as ⟨acc, hacc⟩
  have hwin : (∀ j, j < 64 → byteAt block j = 0) ↔
      (∀ j, j < 64 → byteAt bytes (start.val + j) = 0) := by
    constructor
    · intro h j hj
      rw [← byteAt_slice block bytes start.val hb hbound j hj]
      exact h j hj
    · intro h j hj
      rw [byteAt_slice block bytes start.val hb hbound j hj]
      exact h j hj
  rw [decide_eq_true_eq, ← U8.val_eq_zero_iff, hacc, hwin, forall_window_iff]

theorem last_nonzero_below_loop_spec (bytes : Slice Std.U8) (bound : Nat) (i : Std.Usize)
    (hbound : bound ≤ bytes.length) (hi : i.val ≤ bound)
    (hzero : ∀ j, i.val ≤ j → j < bound → byteAt bytes j = 0) :
    tls_core.protected.last_nonzero_below_loop bytes i ⦃ r =>
      IsLastNonzeroBelow bytes bound r ⦄ := by
  unfold tls_core.protected.last_nonzero_below_loop
  apply Aeneas.Std.loop.spec_decr_nat (fun i' => i'.val)
    (fun i' => i'.val ≤ bound ∧ ∀ j, i'.val ≤ j → j < bound → byteAt bytes j = 0)
    _ _ _ _ ⟨hi, hzero⟩
  rintro i' ⟨hi', hz⟩
  unfold tls_core.protected.last_nonzero_below_loop.body
  split
  · step*
    · have hne : i2 ≠ 0#u8 := by simpa using ‹(i2 != 0#u8) = true›
      have hlt : i1.val < bytes.val.length := by agrind
      have hnz : byteAt bytes i1.val = i2.val := by
        simp [byteAt, i2_post, List.getElem?_eq_getElem hlt]
      refine ⟨by agrind, by rw [hnz]; exact fun h => hne ((U8.val_eq_zero_iff i2).mp h),
        fun j h1 h2 => hz j (by agrind) h2⟩
    · have hlt : i1.val < bytes.val.length := by agrind
      have hz0 : byteAt bytes i1.val = i2.val := by
        simp [byteAt, i2_post, List.getElem?_eq_getElem hlt]
      have hz0' : i2.val = 0 := by simpa using ‹¬(i2 != 0#u8) = true›
      refine ⟨by agrind, fun j h1 h2 => ?_, by agrind⟩
      by_cases hj : j = i1.val
      · rw [hj, hz0, hz0']
      · exact hz j (by agrind) h2
  · simp only [WP.spec_ok]
    intro j hj
    exact hz j (by agrind) hj

theorem last_nonzero_loop_spec (bytes : Slice Std.U8) (e : Std.Usize)
    (he : e.val ≤ bytes.length)
    (hzero : ∀ j, e.val ≤ j → j < bytes.length → byteAt bytes j = 0) :
    tls_core.protected.last_nonzero_loop bytes e ⦃ r =>
      r.val ≤ bytes.length ∧
      (∀ j, r.val ≤ j → j < bytes.length → byteAt bytes j = 0) ∧
      (r.val < 64 ∨ ∃ j, r.val - 64 ≤ j ∧ j < r.val ∧ byteAt bytes j ≠ 0) ⦄ := by
  unfold tls_core.protected.last_nonzero_loop
  apply Aeneas.Std.loop.spec_decr_nat (fun e' => e'.val)
    (fun e' => e'.val ≤ bytes.length ∧ ∀ j, e'.val ≤ j → j < bytes.length → byteAt bytes j = 0)
    _ _ _ _ ⟨he, hzero⟩
  rintro e' ⟨he', hz⟩
  unfold tls_core.protected.last_nonzero_loop.body
  rw [scan_block_eq]
  split
  · step*
    step with block_is_zero_spec as ⟨b, hb⟩
    split
    · simp only [WP.spec_ok]
      refine ⟨by agrind, fun j h1 h2 => ?_, by agrind⟩
      by_cases hj : j < e'.val
      · exact hb.mp ‹b = true› j h1 (by agrind)
      · exact hz j (by agrind) h2
    · simp only [WP.spec_ok]
      refine ⟨he', hz, Or.inr ?_⟩
      by_contra hc
      exact ‹¬b = true› (hb.mpr fun j h1 h2 =>
        Classical.byContradiction fun hz0 => hc ⟨j, by agrind, by agrind, hz0⟩)
  · simp only [WP.spec_ok]
    exact ⟨he', hz, Or.inl (by agrind)⟩

/-- Extending the bound of a last-nonzero result, given zeros in the gap. -/
theorem IsLastNonzeroBelow.extend {bytes : Slice Std.U8} {b n : Nat} {r : Option Std.Usize}
    (h : IsLastNonzeroBelow bytes b r) (hn : b ≤ n)
    (hz : ∀ j, b ≤ j → j < n → byteAt bytes j = 0) :
    IsLastNonzeroBelow bytes n r := by
  cases r
  · intro j hj
    by_cases hjb : j < b
    · exact h j hjb
    · exact hz j (Nat.le_of_not_lt hjb) hj
  · obtain ⟨hk, hnz, hafter⟩ := h
    refine ⟨Nat.lt_of_lt_of_le hk hn, hnz, fun j h1 h2 => ?_⟩
    by_cases hjb : j < b
    · exact hafter j h1 hjb
    · exact hz j (Nat.le_of_not_lt hjb) h2

theorem last_nonzero_spec (bytes : Slice Std.U8) :
    tls_core.protected.last_nonzero bytes ⦃ r =>
      IsLastNonzeroBelow bytes bytes.length r ⦄ := by
  have hlen := Slice.len_val bytes
  have key := last_nonzero_loop_spec bytes (Slice.len bytes) (by agrind)
    (fun j h1 h2 => by agrind)
  unfold tls_core.protected.last_nonzero
  dsimp only
  refine WP.spec_bind key ?_
  rintro e1 ⟨hle, hz, _⟩
  unfold tls_core.protected.last_nonzero_below
  apply WP.spec_mono (last_nonzero_below_loop_spec bytes e1.val e1 hle (Nat.le_refl _)
    (fun j h1 h2 => by agrind))
  intro r hr
  exact IsLastNonzeroBelow.extend hr hle hz

/-- The specification determines the result: at most one index satisfies it. -/
theorem IsLastNonzeroBelow.unique {bytes : Slice Std.U8} {n : Nat} {r r' : Option Std.Usize}
    (h : IsLastNonzeroBelow bytes n r) (h' : IsLastNonzeroBelow bytes n r') : r = r' := by
  rcases r with _ | k
  · rcases r' with _ | k'
    · rfl
    · obtain ⟨hk', hnz', _⟩ := h'
      exact absurd (h k'.val hk') hnz'
  · obtain ⟨hk, hnz, hafter⟩ := h
    rcases r' with _ | k'
    · exact absurd (h' k.val hk) hnz
    · obtain ⟨hk', hnz', hafter'⟩ := h'
      rcases lt_trichotomy k.val k'.val with hlt | heq | hgt
      · exact absurd (hafter k'.val hlt hk') hnz'
      · exact congrArg some (UScalar.eq_of_val_eq heq)
      · exact absurd (hafter' k.val hgt hk) hnz

/-- The Rust `last_nonzero` returns the index that the specification determines, and it
cannot fail. -/
theorem last_nonzero_refines (bytes : Slice Std.U8) :
    ∃ r, tls_core.protected.last_nonzero bytes = ok r ∧
      IsLastNonzeroBelow bytes bytes.length r :=
  WP.spec_imp_exists (last_nonzero_spec bytes)

#print axioms Tls13.Scan.last_nonzero_refines
#print axioms Tls13.Scan.IsLastNonzeroBelow.unique
#print axioms Tls13.Scan.last_nonzero_spec

end Tls13.Scan
