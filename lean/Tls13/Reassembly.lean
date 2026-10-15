import Init

namespace Tls13

def maxHandshakeBody : Nat := 16777215

/-- The u24 wire bound makes adding the four-byte header safe even on 32-bit usize. -/
def checkedHandshakeTotal (body cap : Nat) : Option Nat :=
  if body ≤ maxHandshakeBody ∧ body ≤ cap then some (body + 4) else none

theorem handshakeTotal_bounds (body cap total : Nat)
    (ok : checkedHandshakeTotal body cap = some total) :
    total = body + 4 ∧ total ≤ cap + 4 ∧ total ≤ 16777219 ∧ total < 4294967296 := by
  unfold checkedHandshakeTotal maxHandshakeBody at ok
  split at ok <;> simp_all <;> omega

theorem handshakeTotal_accepts (body cap : Nat)
    (wire : body ≤ maxHandshakeBody) (configured : body ≤ cap) :
    checkedHandshakeTotal body cap = some (body + 4) := by
  simp [checkedHandshakeTotal, wire, configured]

theorem handshakeTotal_rejects (body cap : Nat)
    (oversized : maxHandshakeBody < body ∨ cap < body) :
    checkedHandshakeTotal body cap = none := by
  unfold checkedHandshakeTotal
  split <;> simp_all <;> omega

/-- Greedy copy into a single retained message; all counts are mathematical naturals. -/
def copyProgress (buffered target inputRemaining : Nat) : Nat :=
  min inputRemaining (target - buffered)

theorem copyProgress_bounds (buffered target inputRemaining : Nat)
    (wellFormed : buffered ≤ target) :
    copyProgress buffered target inputRemaining ≤ inputRemaining ∧
    buffered + copyProgress buffered target inputRemaining ≤ target := by
  simp only [copyProgress, Nat.min_def]
  split <;> omega

/-- Maximal local progress under input availability and the fixed retained-message target.
This is not a claim about CPU time or throughput. -/
theorem copyProgress_maximal (buffered target inputRemaining candidate : Nat)
    (available : candidate ≤ inputRemaining) (fits : buffered + candidate ≤ target) :
    candidate ≤ copyProgress buffered target inputRemaining := by
  simp only [copyProgress, Nat.min_def]
  split <;> omega

/-- Body copying starts only after a validated four-byte header is retained. -/
def reassemblyStep (body cap buffered inputRemaining : Nat) : Option (Nat × Nat) := do
  let total ← checkedHandshakeTotal body cap
  if 4 ≤ buffered ∧ buffered ≤ total then
    let consumed := copyProgress buffered total inputRemaining
    some (consumed, buffered + consumed)
  else none

theorem reassembly_rejects_before_copy (body cap buffered inputRemaining : Nat)
    (oversized : maxHandshakeBody < body ∨ cap < body) :
    reassemblyStep body cap buffered inputRemaining = none := by
  simp [reassemblyStep, handshakeTotal_rejects body cap oversized]

theorem reassemblyStep_bounded (body cap buffered inputRemaining consumed after : Nat)
    (ok : reassemblyStep body cap buffered inputRemaining = some (consumed, after)) :
    consumed ≤ inputRemaining ∧ after = buffered + consumed ∧
    after ≤ body + 4 ∧ after ≤ cap + 4 ∧ after ≤ 16777219 := by
  unfold reassemblyStep checkedHandshakeTotal at ok
  split at ok <;> simp_all
  have progress := copyProgress_bounds buffered (body + 4) inputRemaining (by omega)
  simp only [maxHandshakeBody] at *
  omega

end Tls13
