import Init

namespace Tls13

/-- Overflow-avoiding ceiling division, with a caller obligation `0 < limit`. -/
def recordCount (n limit : Nat) : Nat :=
  n / limit + if n % limit = 0 then 0 else 1

/-- The computed number has enough aggregate capacity. -/
theorem recordCount_feasible (n limit : Nat) (positive : 0 < limit) :
    n ≤ recordCount n limit * limit := by
  have decomposition := Nat.div_add_mod n limit
  have remainder := Nat.mod_lt n positive
  unfold recordCount
  split <;> rename_i h
  · simp only [Nat.add_zero]
    rw [Nat.mul_comm limit (n / limit)] at decomposition
    omega
  · rw [Nat.add_mul, Nat.one_mul, Nat.mul_comm (n / limit) limit]
    omega

/-- Any number of capacity-limited records covering n bytes is at least our count. -/
theorem recordCount_minimal (n limit k : Nat) (positive : 0 < limit)
    (covers : n ≤ k * limit) : recordCount n limit ≤ k := by
  have decomposition := Nat.div_add_mod n limit
  have quotientBound : n / limit ≤ k := by
    have := (Nat.div_lt_iff_lt_mul positive).mpr
      (Nat.lt_of_le_of_lt covers (by
        rw [Nat.add_mul, Nat.one_mul]
        omega : k * limit < (k + 1) * limit))
    omega
  unfold recordCount
  split <;> rename_i h
  · omega
  · have unequal : n / limit ≠ k := by
      intro eq
      rw [eq, Nat.mul_comm limit k] at decomposition
      omega
    omega

/-- At most n nonempty records; in particular the final +1 fits when n fits. -/
theorem recordCount_le_input (n limit : Nat) (positive : 0 < limit) :
    recordCount n limit ≤ n := by
  apply recordCount_minimal n limit n positive
  have := Nat.mul_le_mul_left n positive
  simpa using this

/-- A concrete feasible partition: full records then an optional remainder. -/
def recordPartition (n limit : Nat) : List Nat :=
  List.replicate (n / limit) limit ++
    if n % limit = 0 then [] else [n % limit]

theorem recordPartition_sum (n limit : Nat) :
    (recordPartition n limit).sum = n := by
  have decomposition := Nat.div_add_mod n limit
  unfold recordPartition
  split <;> rename_i h
  · simp [List.sum_replicate_nat, h, Nat.mul_comm] at *
    omega
  · simp [List.sum_replicate_nat, Nat.mul_comm]
    exact decomposition

theorem recordPartition_length (n limit : Nat) :
    (recordPartition n limit).length = recordCount n limit := by
  unfold recordPartition recordCount
  split <;> simp

theorem recordPartition_bounded (n limit : Nat) (positive : 0 < limit) :
    ∀ x ∈ recordPartition n limit, 0 < x ∧ x ≤ limit := by
  intro x hx
  unfold recordPartition at hx
  simp only [List.mem_append] at hx
  rcases hx with h | h
  · have eq : x = limit := (List.mem_replicate.mp h).2
    subst x
    omega
  · split at h <;> rename_i remainder
    · simp at h
    · simp only [List.mem_singleton] at h
      subst x
      have := Nat.mod_lt n positive
      omega

theorem partition_capacity (parts : List Nat) (limit : Nat)
    (bounded : ∀ x ∈ parts, x ≤ limit) : parts.sum ≤ parts.length * limit := by
  induction parts with
  | nil => simp
  | cons x xs ih =>
    have hx := bounded x (by simp)
    have hxs := ih (by intro y hy; exact bounded y (by simp [hy]))
    simp only [List.sum_cons, List.length_cons, Nat.add_mul, Nat.one_mul]
    omega

/-- True minimum over all finite capacity-respecting partitions with equal payload. -/
theorem recordCount_partition_optimal (n limit : Nat) (positive : 0 < limit)
    (parts : List Nat) (payload : parts.sum = n)
    (bounded : ∀ x ∈ parts, x ≤ limit) : recordCount n limit ≤ parts.length := by
  apply recordCount_minimal n limit parts.length positive
  rw [← payload]
  exact partition_capacity parts limit bounded

/-- A fixed nonnegative overhead per record is minimized by the same partition. -/
theorem fixed_overhead_optimal (n limit overhead : Nat) (positive : 0 < limit)
    (parts : List Nat) (payload : parts.sum = n)
    (bounded : ∀ x ∈ parts, x ≤ limit) :
    n + overhead * recordCount n limit ≤ n + overhead * parts.length := by
  exact Nat.add_le_add_left
    (Nat.mul_le_mul_left overhead
      (recordCount_partition_optimal n limit positive parts payload bounded)) n

end Tls13
