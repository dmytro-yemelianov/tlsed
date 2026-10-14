import Init

namespace Tls13

def validInnerType (kind contentLength : Nat) : Bool :=
  decide (kind = 23 ∨ (kind = 22 ∧ 0 < contentLength) ∨
    (kind = 21 ∧ contentLength = 2))

def innerAccepted (kind contentLength paddingLength limit : Nat) : Bool :=
  decide (1 ≤ limit ∧ limit ≤ 16385 ∧ contentLength + 1 + paddingLength ≤ limit) &&
    validInnerType kind contentLength

/-- Numeric guard corresponding to the production checked inner-length helper. -/
def checkedInnerLength (contentLength paddingLength limit : Nat) : Option Nat :=
  if 1 ≤ limit ∧ limit ≤ 16385 ∧ contentLength + 1 + paddingLength ≤ limit then
    some (contentLength + 1 + paddingLength)
  else none

theorem checkedInnerLength_matches (kind contentLength paddingLength limit : Nat) :
    ((checkedInnerLength contentLength paddingLength limit).isSome &&
      validInnerType kind contentLength) = innerAccepted kind contentLength paddingLength limit := by
  unfold checkedInnerLength innerAccepted
  split <;> rename_i h <;> simp [h]

theorem innerAccepted_bounds (kind contentLength paddingLength limit : Nat)
    (ok : innerAccepted kind contentLength paddingLength limit = true) :
    contentLength ≤ 16384 ∧ contentLength + 1 + paddingLength ≤ limit ∧
    contentLength + 1 + paddingLength ≤ 16385 ∧
    contentLength + 1 + paddingLength + 16 ≤ 16640 := by
  simp only [innerAccepted, Bool.and_eq_true, decide_eq_true_eq] at ok
  omega

theorem innerAccepted_type (kind contentLength paddingLength limit : Nat)
    (ok : innerAccepted kind contentLength paddingLength limit = true) :
    kind = 23 ∨ (kind = 22 ∧ 0 < contentLength) ∨ (kind = 21 ∧ contentLength = 2) := by
  simp only [innerAccepted, Bool.and_eq_true, decide_eq_true_eq] at ok
  simpa only [validInnerType, decide_eq_true_eq] using ok.2

theorem innerAccepted_rejects_overflow (kind contentLength paddingLength limit : Nat)
    (oversized : 16385 < contentLength + 1 + paddingLength) :
    innerAccepted kind contentLength paddingLength limit = false := by
  have fail : decide (1 ≤ limit ∧ limit ≤ 16385 ∧
      contentLength + 1 + paddingLength ≤ limit) = false := by
    simp only [decide_eq_false_iff_not]
    omega
  simp [innerAccepted, fail]

/-- Decode already-decrypted bytes in reverse order, skipping exactly zero padding. -/
def stripInnerPadding : List Nat → Option (Nat × List Nat)
  | [] => none
  | byte :: rest => if byte = 0 then stripInnerPadding rest else some (byte, rest.reverse)

/-- Success identifies a nonzero type and trailing padding consisting only of zero bytes. -/
theorem stripInnerPadding_shape (reversed : List Nat) (kind : Nat) (content : List Nat)
    (ok : stripInnerPadding reversed = some (kind, content)) :
    kind ≠ 0 ∧ ∃ padding : Nat,
      reversed = List.replicate padding 0 ++ kind :: content.reverse := by
  induction reversed with
  | nil => simp [stripInnerPadding] at ok
  | cons byte rest ih =>
    simp only [stripInnerPadding] at ok
    split at ok <;> rename_i h
    · obtain ⟨nonzero, padding, shape⟩ := ih ok
      refine ⟨nonzero, padding + 1, ?_⟩
      subst byte
      simp [List.replicate_succ, shape]
    · simp only [Option.some.injEq, Prod.mk.injEq] at ok
      obtain ⟨rfl, rfl⟩ := ok
      exact ⟨h, 0, by simp⟩

theorem stripInnerPadding_length (reversed : List Nat) (kind : Nat) (content : List Nat)
    (ok : stripInnerPadding reversed = some (kind, content)) :
    content.length + 1 ≤ reversed.length := by
  obtain ⟨_, padding, shape⟩ := stripInnerPadding_shape reversed kind content ok
  have := congrArg List.length shape
  simp only [List.length_append, List.length_replicate, List.length_cons,
    List.length_reverse] at this
  omega

theorem all_zero_inner_rejected (count : Nat) :
    stripInnerPadding (List.replicate count 0) = none := by
  induction count with
  | zero => rfl
  | succ count ih => simpa [List.replicate_succ, stripInnerPadding] using ih

/-- AEAD success is evidence supplied by a maintained provider. Returned content is
still subject to connection authentication before application delivery. -/
def openInner (aeadOk : Bool) (bytes : List Nat) (limit : Nat) : Option (Nat × List Nat) :=
  if aeadOk ∧ 1 ≤ limit ∧ limit ≤ 16385 ∧ bytes.length ≤ limit then do
    let (kind, content) ← stripInnerPadding bytes.reverse
    if validInnerType kind content.length then some (kind, content) else none
  else none

theorem openInner_requires_authentication (aeadOk : Bool) (bytes : List Nat) (limit kind : Nat)
    (content : List Nat) (ok : openInner aeadOk bytes limit = some (kind, content)) :
    aeadOk = true ∧ validInnerType kind content.length = true ∧
    bytes.length ≤ limit ∧ bytes.length ≤ 16385 ∧
    stripInnerPadding bytes.reverse = some (kind, content) := by
  unfold openInner at ok
  split at ok <;> simp_all
  cases scan : stripInnerPadding bytes.reverse with
  | none => simp [scan] at ok
  | some decoded =>
    obtain ⟨tag, payload⟩ := decoded
    simp only [scan, Option.bind_some] at ok
    split at ok <;> simp_all <;> omega

theorem openInner_content_bound (aeadOk : Bool) (bytes : List Nat) (limit kind : Nat)
    (content : List Nat) (ok : openInner aeadOk bytes limit = some (kind, content)) :
    content.length ≤ 16384 := by
  obtain ⟨_, _, _, bound, decoded⟩ := openInner_requires_authentication aeadOk bytes limit kind content ok
  have length := stripInnerPadding_length bytes.reverse kind content decoded
  simp only [List.length_reverse] at length
  omega

theorem openInner_padding_shape (aeadOk : Bool) (bytes : List Nat) (limit kind : Nat)
    (content : List Nat) (ok : openInner aeadOk bytes limit = some (kind, content)) :
    ∃ padding : Nat, bytes = content ++ [kind] ++ List.replicate padding 0 := by
  have decoded := (openInner_requires_authentication aeadOk bytes limit kind content ok).2.2.2.2
  obtain ⟨_, padding, shape⟩ := stripInnerPadding_shape bytes.reverse kind content decoded
  refine ⟨padding, ?_⟩
  have reversed := congrArg List.reverse shape
  simpa [List.reverse_append, List.reverse_cons, List.append_assoc] using reversed

/-- Mathematical release buffer: malformed or unauthenticated input releases no bytes. -/
def releasedInnerBytes (aeadOk : Bool) (bytes : List Nat) (limit : Nat) : List Nat :=
  match openInner aeadOk bytes limit with
  | some (_, content) => content
  | none => []

theorem failed_aead_releases_empty (bytes : List Nat) (limit : Nat) :
    releasedInnerBytes false bytes limit = [] := by
  simp [releasedInnerBytes, openInner]

/-- Provider outputs must account for exactly the fixed authentication-tag length. -/
def openProtected (aeadOk : Bool) (ciphertextLength : Nat) (bytes : List Nat)
    (limit : Nat) : Option (Nat × List Nat) :=
  if bytes.length + 16 = ciphertextLength then openInner aeadOk bytes limit else none

theorem provider_length_mismatch_rejected (aeadOk : Bool) (ciphertextLength : Nat)
    (bytes : List Nat) (limit : Nat) (mismatch : bytes.length + 16 ≠ ciphertextLength) :
    openProtected aeadOk ciphertextLength bytes limit = none := by
  simp [openProtected, mismatch]

theorem openProtected_bounds (aeadOk : Bool) (ciphertextLength : Nat)
    (bytes : List Nat) (limit kind : Nat) (content : List Nat)
    (ok : openProtected aeadOk ciphertextLength bytes limit = some (kind, content)) :
    aeadOk = true ∧ 17 ≤ ciphertextLength ∧ ciphertextLength ≤ 16401 ∧
    ciphertextLength ≤ 16640 ∧ bytes.length + 16 = ciphertextLength := by
  unfold openProtected at ok
  split at ok <;> simp_all
  have authenticated := openInner_requires_authentication aeadOk bytes limit kind content ok
  have decodedLength := stripInnerPadding_length bytes.reverse kind content authenticated.2.2.2.2
  simp only [List.length_reverse] at decodedLength
  refine ⟨authenticated.1, ?_⟩
  omega

theorem failed_aead_cannot_open (ciphertextLength : Nat) (bytes : List Nat) (limit : Nat) :
    openProtected false ciphertextLength bytes limit = none := by
  simp [openProtected, openInner]

end Tls13
