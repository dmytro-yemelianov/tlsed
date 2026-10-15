import Tls13.Segmentation
import Tls13.Zeroization

namespace Tls13

/-- Each chunk is cleared in place before advancing to the next one. The operation
models byte states, not volatile instructions, temporary copies, or barriers. -/
def clearPlainChunks (memory : PlainMemory) (start : Nat) : List Nat → PlainMemory
  | [] => memory
  | size :: rest => clearPlainChunks (consumedPlaintext memory start size) (start + size) rest

theorem clearAdjacent_ranges (memory : PlainMemory) (start first second : Nat) :
    consumedPlaintext (consumedPlaintext memory start first) (start + first) second =
      consumedPlaintext memory start (first + second) := by
  funext i
  by_cases left : start ≤ i ∧ i < start + first
  · have right : ¬ (start + first ≤ i ∧ i < start + first + second) := by omega
    have whole : start ≤ i ∧ i < start + (first + second) := by omega
    simp [consumedPlaintext, left, right, whole]
  · by_cases right : start + first ≤ i ∧ i < start + first + second
    · have whole : start ≤ i ∧ i < start + (first + second) := by omega
      simp [consumedPlaintext, right, whole]
    · have whole : ¬ (start ≤ i ∧ i < start + (first + second)) := by omega
      simp [consumedPlaintext, left, right, whole]

theorem clearPlainChunks_equals_range (memory : PlainMemory) (start : Nat) (parts : List Nat) :
    clearPlainChunks memory start parts = consumedPlaintext memory start parts.sum := by
  induction parts generalizing memory start with
  | nil => exact (consumedPlaintext_zero memory start).symm
  | cons size rest ih =>
    simp only [clearPlainChunks, List.sum_cons]
    rw [ih, clearAdjacent_ranges]

/-- Quotient/remainder partition; no overflowing n+width-1 ceiling expression. -/
def chunkedZeroization (memory : PlainMemory) (start count width : Nat) : PlainMemory :=
  clearPlainChunks memory start (recordPartition count width)

theorem zeroizeChunk_partition (count width : Nat) (positive : 0 < width) :
    (recordPartition count width).sum = count ∧
    (recordPartition count width).length = recordCount count width ∧
    (∀ size ∈ recordPartition count width, 0 < size ∧ size ≤ width) := by
  exact ⟨recordPartition_sum count width, recordPartition_length count width,
    recordPartition_bounded count width positive⟩

theorem zeroizeChunk_decomposition (count width : Nat) (positive : 0 < width) :
    (count / width) * width + count % width = count ∧
    count % width < width ∧ (count / width) * width ≤ count := by
  have splitCount := Nat.div_add_mod count width
  have small := Nat.mod_lt count positive
  rw [Nat.mul_comm width (count / width)] at splitCount
  omega

/-- Every cumulative endpoint in any partition fits whenever the whole range fits. -/
theorem zeroizeChunk_endpoints_fit (start count maximum : Nat) (before after : List Nat)
    (partition : (before ++ after).sum = count) (fits : start + count ≤ maximum) :
    start ≤ start + before.sum ∧ start + before.sum ≤ start + count ∧
    start + before.sum ≤ maximum := by
  simp only [List.sum_append] at partition
  omega

theorem zeroizeChunk_machine_bounds (start count width maximum : Nat) (positive : 0 < width)
    (fits : start + count ≤ maximum) :
    (count / width) * width ≤ maximum ∧
    start + (count / width) * width ≤ maximum ∧
    start + (count / width) * width + count % width ≤ maximum ∧
    recordCount count width ≤ maximum := by
  have decomposition := zeroizeChunk_decomposition count width positive
  have chunks := recordCount_le_input count width positive
  omega

/-- Minimum number of nonempty clearing chunks with fixed positive capacity.
This says nothing about the best width, barriers, CPU instructions, or latency. -/
theorem zeroizeChunk_count_minimal (count width : Nat) (positive : 0 < width)
    (parts : List Nat) (covers : parts.sum = count)
    (bounded : ∀ size ∈ parts, size ≤ width) :
    (recordPartition count width).length ≤ parts.length := by
  rw [recordPartition_length]
  exact recordCount_partition_optimal count width positive parts covers bounded

theorem chunkedZeroization_equals_range (memory : PlainMemory) (start count width : Nat) :
    chunkedZeroization memory start count width = consumedPlaintext memory start count := by
  simp [chunkedZeroization, clearPlainChunks_equals_range, recordPartition_sum]

theorem chunkedZeroization_zero (memory : PlainMemory) (start width : Nat) :
    chunkedZeroization memory start 0 width = memory := by
  rw [chunkedZeroization_equals_range, consumedPlaintext_zero]

theorem chunkedZeroization_inside (memory : PlainMemory) (start count width i : Nat)
    (lower : start ≤ i) (upper : i < start + count) :
    chunkedZeroization memory start count width i = 0 := by
  rw [chunkedZeroization_equals_range]
  exact consumedPlaintext_inside memory start count i lower upper

theorem chunkedZeroization_outside (memory : PlainMemory) (start count width i : Nat)
    (outside : i < start ∨ start + count ≤ i) :
    chunkedZeroization memory start count width i = memory i := by
  rw [chunkedZeroization_equals_range]
  exact consumedPlaintext_outside memory start count i outside

theorem chunkedZeroization_read_clean (memory : PlainMemory) (loan content offset requested width : Nat)
    (clean : CleanPlaintext memory loan content offset) :
    CleanPlaintext (chunkedZeroization memory offset (readAmount content offset requested) width)
      loan content (offset + readAmount content offset requested) := by
  rw [chunkedZeroization_equals_range]
  exact readPlaintext_preserves_clean memory loan content offset requested clean

/-- Multiple reads using the same fixed chunk width; zero requests are permitted. -/
inductive ChunkedPlainReads (width content : Nat) : PlainMemory → Nat → PlainMemory → Nat → Prop where
  | refl (memory offset) : ChunkedPlainReads width content memory offset memory offset
  | step {initial first memory offset}
      (prior : ChunkedPlainReads width content initial first memory offset) (requested : Nat) :
      ChunkedPlainReads width content initial first
        (chunkedZeroization memory offset (readAmount content offset requested) width)
        (offset + readAmount content offset requested)

theorem chunkedPlainReads_agree (width content first last : Nat) (initial final : PlainMemory)
    (reads : ChunkedPlainReads width content initial first final last) :
    PlainReads content initial first final last := by
  induction reads with
  | refl => exact PlainReads.refl _ _
  | step prior requested ih =>
    rw [chunkedZeroization_equals_range]
    exact PlainReads.step ih requested

theorem chunkedPlainReads_complete_zero (width loan content first last : Nat) (initial final : PlainMemory)
    (reads : ChunkedPlainReads width content initial first final last)
    (clean : CleanPlaintext initial loan content first) (complete : last = content) :
    ∀ i, i < loan → final i = 0 := by
  exact plainReads_complete_zero loan content first last initial final
    (chunkedPlainReads_agree width content first last initial final reads) clean complete

/-- Byte head, any number of fixed-width words, and byte tail. No maximality
or address alignment is inferred from this abstract partition. Empty head/tail
entries have identity effects; the implementation may omit their calls. -/
def alignedClearParts (head width words tail : Nat) : List Nat :=
  [head] ++ List.replicate words width ++ [tail]

theorem alignedClearParts_sum (head width words tail : Nat) :
    (alignedClearParts head width words tail).sum = head + words * width + tail := by
  simp [alignedClearParts, List.sum_replicate_nat, Nat.add_assoc]

/-- Exact coverage is sufficient even if a library returns a nonmaximal middle. -/
theorem alignedClear_equals_range (memory : PlainMemory) (start count head width words tail : Nat)
    (covers : head + words * width + tail = count) :
    clearPlainChunks memory start (alignedClearParts head width words tail) =
      consumedPlaintext memory start count := by
  rw [clearPlainChunks_equals_range, alignedClearParts_sum, covers]

theorem alignedClear_machine_bounds (start count head width words tail maximum : Nat)
    (covers : head + words * width + tail = count) (fits : start + count ≤ maximum) :
    words * width ≤ maximum ∧ start + head ≤ maximum ∧
    start + head + words * width ≤ maximum ∧
    start + head + words * width + tail ≤ maximum := by
  omega

theorem alignedClear_read_clean (memory : PlainMemory)
    (loan content offset requested head width words tail : Nat)
    (covers : head + words * width + tail = readAmount content offset requested)
    (clean : CleanPlaintext memory loan content offset) :
    CleanPlaintext (clearPlainChunks memory offset (alignedClearParts head width words tail))
      loan content (offset + readAmount content offset requested) := by
  rw [alignedClear_equals_range memory offset _ head width words tail covers]
  exact readPlaintext_preserves_clean memory loan content offset requested clean

/-- Optional stronger hypothesis: for a fixed head, the remaining tail is smaller
than one word. A library's safe alignment API is not assumed to promise this. -/
theorem alignedClear_maximal_decomposition (count head width words tail : Nat)
    (positive : 0 < width) (covers : head + words * width + tail = count)
    (maximalMiddle : tail < width) :
    (count - head) / width = words ∧ (count - head) % width = tail := by
  have lower : words ≤ (count - head) / width := by
    apply (Nat.le_div_iff_mul_le positive).mpr
    omega
  have upper : (count - head) / width < words + 1 := by
    apply (Nat.div_lt_iff_lt_mul positive).mpr
    simp only [Nat.add_mul, Nat.one_mul]
    omega
  have quotient : (count - head) / width = words := by omega
  have remainder := Nat.div_add_mod (count - head) width
  rw [quotient, Nat.mul_comm width words] at remainder
  exact ⟨quotient, by omega⟩

/-- Conditional minimum number of width-bounded chunks after the fixed head.
It does not count per-byte head/tail stores, barriers, alignment choices, or CPU time. -/
theorem alignedClear_maximal_count_minimal (count head width words tail : Nat)
    (positive : 0 < width) (covers : head + words * width + tail = count)
    (maximalMiddle : tail < width) (parts : List Nat)
    (sameRemaining : parts.sum = count - head) (bounded : ∀ size ∈ parts, size ≤ width) :
    words + (if tail = 0 then 0 else 1) ≤ parts.length := by
  have decomposition := alignedClear_maximal_decomposition count head width words tail
    positive covers maximalMiddle
  have optimal := recordCount_partition_optimal (count - head) width positive parts sameRemaining bounded
  simpa [recordCount, decomposition.1, decomposition.2] using optimal

end Tls13
