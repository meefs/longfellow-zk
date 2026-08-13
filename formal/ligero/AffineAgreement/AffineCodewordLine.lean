import AffineAgreement.DecoderData

/-!
# Affine codeword lines

For a received line `u + αv`, an affine codeword line is `c₀ + αc₁`
with both coefficients in the code.  Their difference is the residual line;
the union of its two coefficient supports is its active (common error)
support.  A selected decoding *follows* the codeword line when it equals the
line at its parameter.
-/

namespace AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

namespace Internal

/-- An affine line contained in the code. -/
structure AffineCodewordLine {n e m : ℕ} {C : LinearCode F n}
    {u v : Word F n} (D : DecoderData (e := e) (m := m) C u v) where
  base : Word F n
  direction : Word F n
  base_mem : base ∈ C
  direction_mem : direction ∈ C

namespace AffineCodewordLine

variable {n e m : ℕ} {C : LinearCode F n}
  {u v : Word F n} (D : DecoderData (e := e) (m := m) C u v)

/-- The residual line between the received line and this codeword line. -/
def residualLine (line : AffineCodewordLine D) (a : F) : Word F n :=
  affineWord (u - line.base) (v - line.direction) a

/-- The common error support of the residual line. -/
def activeSupport (line : AffineCodewordLine D) : Finset (Fin n) :=
  jointSupport (u - line.base) (v - line.direction)

/-- The line is an `h`-explanation of the received line when its active
support has at most `h` coordinates. -/
def hExplains (line : AffineCodewordLine D) (h : ℕ) : Prop :=
  (line.activeSupport D).card ≤ h

/-- Selected decoding parameters that follow this affine codeword line. -/
def followingParameters (line : AffineCodewordLine D) : Finset F :=
  D.parameters.filter fun a ↦
    D.codeword a = affineWord line.base line.direction a

theorem followingParameters_subset (line : AffineCodewordLine D) :
    line.followingParameters D ⊆ D.parameters :=
  Finset.filter_subset _ _

/-- At a following parameter, the selected decoding equals the codeword
line. -/
theorem selectedDecoding_eq (line : AffineCodewordLine D) {a : F}
    (ha : a ∈ line.followingParameters D) :
    D.codeword a = affineWord line.base line.direction a :=
  (Finset.mem_filter.mp ha).2

/-- Two parameterized affine codeword lines that share two distinct selected
decodings are equal. -/
theorem eq_of_two_parameters (first second : AffineCodewordLine D) {a b : F}
    (hab : a ≠ b)
    (haFirst : a ∈ first.followingParameters D)
    (hbFirst : b ∈ first.followingParameters D)
    (haSecond : a ∈ second.followingParameters D)
    (hbSecond : b ∈ second.followingParameters D) : first = second := by
  have ha : affineWord first.base first.direction a =
      affineWord second.base second.direction a :=
    (first.selectedDecoding_eq D haFirst).symm.trans
      (second.selectedDecoding_eq D haSecond)
  have hb : affineWord first.base first.direction b =
      affineWord second.base second.direction b :=
    (first.selectedDecoding_eq D hbFirst).symm.trans
      (second.selectedDecoding_eq D hbSecond)
  have hdirection : first.direction = second.direction := by
    funext i
    have ha' := congrFun ha i
    have hb' := congrFun hb i
    have hmul : (b - a) * (first.direction i - second.direction i) = 0 := by
      calc
        (b - a) * (first.direction i - second.direction i) =
            (affineWord first.base first.direction b i -
              affineWord second.base second.direction b i) -
            (affineWord first.base first.direction a i -
              affineWord second.base second.direction a i) := by
          simp only [affineWord_apply]
          ring
        _ = 0 := by rw [hb', ha']; ring
    exact sub_eq_zero.mp ((mul_eq_zero.mp hmul).resolve_left
      (sub_ne_zero.mpr hab.symm))
  have hbase : first.base = second.base := by
    funext i
    have ha' := congrFun ha i
    rw [hdirection] at ha'
    simpa only [affineWord_apply, add_left_inj] using ha'
  cases first
  cases second
  simp_all

end AffineCodewordLine

end Internal

export Internal (AffineCodewordLine)

namespace AffineCodewordLine

export Internal.AffineCodewordLine (residualLine activeSupport hExplains
  followingParameters followingParameters_subset selectedDecoding_eq
  eq_of_two_parameters)

end AffineCodewordLine

end AffineAgreement
