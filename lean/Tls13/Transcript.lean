import Init

namespace Tls13

/-- Ghost message history: the Rust implementation streams bytes instead of retaining this list. -/
structure TranscriptMessage where
  kind : Nat
  body : List Nat
  deriving DecidableEq, Repr

def encodeTranscriptMessage (message : TranscriptMessage) : List Nat :=
  [message.kind, message.body.length / 65536, message.body.length / 256 % 256,
    message.body.length % 256] ++ message.body

structure TranscriptState where
  messages : List TranscriptMessage := []
  retried : Bool := false
  failed : Bool := false
  deriving DecidableEq, Repr

def transcriptBytes (state : TranscriptState) : List Nat :=
  state.messages.flatMap encodeTranscriptMessage

def transcriptSnapshot (hash : List Nat → List Nat) (state : TranscriptState) : List Nat :=
  hash (transcriptBytes state)

/-- Append presumes the encoded-message parser has already accepted a complete message. -/
def appendTranscript (state : TranscriptState) (message : TranscriptMessage) : TranscriptState :=
  if state.failed then state else { state with messages := state.messages ++ [message] }

theorem transcript_append_order (state : TranscriptState) (message : TranscriptMessage)
    (healthy : state.failed = false) :
    transcriptBytes (appendTranscript state message) =
      transcriptBytes state ++ encodeTranscriptMessage message := by
  simp [appendTranscript, healthy, transcriptBytes, List.flatMap_append]

theorem failed_transcript_cannot_advance (state : TranscriptState) (message : TranscriptMessage)
    (failed : state.failed = true) : appendTranscript state message = state := by
  simp [appendTranscript, failed]

def syntheticMessageHash (hash : List Nat → List Nat) (clientHello : TranscriptMessage) : TranscriptMessage :=
  ⟨254, hash (encodeTranscriptMessage clientHello)⟩

/-- Hash is a parameter; no collision resistance or cryptographic fact is assumed. -/
def tryHrrRewrite (hash : List Nat → List Nat) (state : TranscriptState)
    (hrr : TranscriptMessage) : Option TranscriptState :=
  if state.failed = true ∨ state.retried = true then none
  else match state.messages with
    | [clientHello] =>
      if clientHello.kind = 1 ∧ hrr.kind = 2 then
        some ⟨[syntheticMessageHash hash clientHello, hrr], true, false⟩
      else none
    | _ => none

def rewriteTranscript (hash : List Nat → List Nat) (state : TranscriptState)
    (hrr : TranscriptMessage) : TranscriptState :=
  (tryHrrRewrite hash state hrr).getD { state with failed := true }

theorem hrr_rewrite_exact (hash : List Nat → List Nat) (clientHello hrr : TranscriptMessage)
    (clientKind : clientHello.kind = 1) (serverKind : hrr.kind = 2) :
    tryHrrRewrite hash ⟨[clientHello], false, false⟩ hrr =
      some ⟨[syntheticMessageHash hash clientHello, hrr], true, false⟩ := by
  simp [tryHrrRewrite, clientKind, serverKind]

theorem hrr_rewrite_guarded (hash : List Nat → List Nat) (state next : TranscriptState)
    (hrr : TranscriptMessage) (ok : tryHrrRewrite hash state hrr = some next) :
    state.failed = false ∧ state.retried = false ∧
    ∃ clientHello : TranscriptMessage, state.messages = [clientHello] ∧ clientHello.kind = 1 ∧
      hrr.kind = 2 ∧ next.messages = [syntheticMessageHash hash clientHello, hrr] ∧
      next.retried = true ∧ next.failed = false := by
  by_cases blocked : state.failed = true ∨ state.retried = true
  · simp [tryHrrRewrite, blocked] at ok
  · cases history : state.messages with
    | nil => simp [tryHrrRewrite, blocked, history] at ok
    | cons clientHello tail =>
      cases remaining : tail with
      | nil =>
        simp only [tryHrrRewrite, blocked, ite_false, history, remaining] at ok
        split at ok <;> simp_all
        cases ok
        simp_all
      | cons second rest => simp [tryHrrRewrite, blocked, history, remaining] at ok

theorem hrr_duplicate_rejected (hash : List Nat → List Nat) (state : TranscriptState)
    (hrr : TranscriptMessage) (already : state.retried = true) :
    tryHrrRewrite hash state hrr = none := by simp [tryHrrRewrite, already]

theorem hrr_failure_preserves_and_poisons (hash : List Nat → List Nat) (state : TranscriptState)
    (hrr : TranscriptMessage) (failed : tryHrrRewrite hash state hrr = none) :
    (rewriteTranscript hash state hrr).messages = state.messages ∧
    (rewriteTranscript hash state hrr).failed = true := by
  simp [rewriteTranscript, failed]

theorem hrr_success_binds_rewritten_order (hash : List Nat → List Nat) (state next : TranscriptState)
    (hrr : TranscriptMessage) (ok : tryHrrRewrite hash state hrr = some next) :
    ∃ clientHello : TranscriptMessage, state.messages = [clientHello] ∧
      transcriptBytes next = encodeTranscriptMessage (syntheticMessageHash hash clientHello) ++
        encodeTranscriptMessage hrr := by
  obtain ⟨_, _, clientHello, old, _, _, new, _, _⟩ := hrr_rewrite_guarded hash state next hrr ok
  exact ⟨clientHello, old, by simp [transcriptBytes, new]⟩

theorem synthetic_message_hash_contents (hash : List Nat → List Nat) (clientHello : TranscriptMessage) :
    (syntheticMessageHash hash clientHello).kind = 254 ∧
    (syntheticMessageHash hash clientHello).body = hash (encodeTranscriptMessage clientHello) := by
  exact ⟨rfl, rfl⟩

/-- Verification is explicitly applied to the current ordered transcript snapshot. -/
def verifyTranscriptFinished (hash : List Nat → List Nat)
    (verify : List Nat → List Nat → List Nat → Bool)
    (key tag : List Nat) (state : TranscriptState) : Bool :=
  !state.failed && verify key (transcriptSnapshot hash state) tag

theorem finished_verification_uses_current_snapshot (hash : List Nat → List Nat)
    (verify : List Nat → List Nat → List Nat → Bool)
    (key tag : List Nat) (state : TranscriptState)
    (accepted : verifyTranscriptFinished hash verify key tag state = true) :
    state.failed = false ∧ verify key (transcriptSnapshot hash state) tag = true := by
  simpa [verifyTranscriptFinished] using accepted

/-- Conditional provider-correctness theorem. This assumes verification soundness,
not injectivity or collision-freedom of HMAC/hash, and does not establish identity. -/
theorem finished_binds_current_snapshot (hash : List Nat → List Nat)
    (verify : List Nat → List Nat → List Nat → Bool) (mac : List Nat → List Nat → List Nat)
    (key tag : List Nat) (state : TranscriptState)
    (sound : ∀ digest received, verify key digest received = true → received = mac key digest)
    (accepted : verifyTranscriptFinished hash verify key tag state = true) :
    tag = mac key (transcriptSnapshot hash state) := by
  exact sound _ _ (finished_verification_uses_current_snapshot hash verify key tag state accepted).2

end Tls13
