import JBAgreement.StrongMutual
import SelectedMCA.LineFailure

/-!
# The Johnson-regime bound on one selected-agreement line

`SelectedMCA` bounds, for a single decoder line `u + z·v`, the number of selected
parameters that fail *directional `g`-liftability*: parameters whose selected
codeword agrees with the line point on many coordinates, yet no codeword
direction matches the received direction `v` on all but `g` of them.  Ligero's
soundness stack consumes exactly that count, as
`SelectedMCA.directionallyNonliftableParameters_card_le_direct`, whose hypothesis
is the marked-triples clique condition.

This file supplies the same count from `strong_mutual_johnson` instead, so the
`η³` Johnson-regime radius becomes available to the same consumers.  The bridge
is short because Haböck's *explanation* is strictly stronger than directional
liftability: an explained proximate has `u x = p₀(dom x)` **and**
`v x = p₁(dom x)` at *every* agreement coordinate, so the cancellation support
`supportOn (agreement) (v - p₁)` is empty and liftability holds at `g = 0`, hence
at every `g`.  Consequently

  `directionallyNonliftableParameters D g ⊆ {z | HasUnexplainedProximate … z}`

for every `g`, and `strong_mutual_johnson` bounds the right-hand side.

The one structural hypothesis the clique route does not need is that the code is
Reed–Solomon: the Johnson bound is a statement about polynomials, so the code
must be presented as evaluations of degree-`≤ k` polynomials on an injective
domain.  `RSPresentation` records that presentation.  A dimension-`k`
Reed–Solomon code is presented at degree `k - 1`.
-/

namespace JBAgreement

open CodingTheory SelectedMCA AffineAgreement Polynomial Finset

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/-- A Reed–Solomon presentation of a linear code: an injective evaluation domain
together with the two inclusions identifying `C` with the polynomials of degree
at most `k`.  Only these two directions are used -- `mem_of_natDegree_le` to
return an explaining component to the code, `exists_of_mem` to read a selected
codeword as a polynomial. -/
structure RSPresentation (n k : ℕ) (C : LinearCode F n) where
  /-- The evaluation domain. -/
  dom : Fin n → F
  /-- Distinct coordinates carry distinct evaluation points. -/
  dom_injective : Function.Injective dom
  /-- Every low-degree polynomial evaluates into the code. -/
  mem_of_natDegree_le : ∀ p : F[X], p.natDegree ≤ k → RSeval dom p ∈ C
  /-- Every codeword is the evaluation of a low-degree polynomial. -/
  exists_of_mem : ∀ w ∈ C, ∃ p : F[X], p.natDegree ≤ k ∧ w = RSeval dom p

omit [Fintype F] in
/-- Hamming disagreement is the support of the difference. -/
theorem disagree_eq_supportOn_sub {n : ℕ} (a b : Word F n) :
    disagree a b = supportOn Finset.univ (a - b) := by
  ext j
  simp [mem_supportOn, sub_eq_zero]

omit [Fintype F] in
/-- The disagreement count of two words is the weight of their difference. -/
theorem card_disagree_eq_weight_sub {n : ℕ} (a b : Word F n) :
    (disagree a b).card = weight (a - b) := by
  rw [disagree_eq_supportOn_sub, weight]

omit [Fintype F] in
/-- **An unexplained proximate is exactly what directional nonliftability
provides.**  If the selected codeword at `z` admits no explaining pair, it
witnesses `HasUnexplainedProximate`; conversely an explaining pair makes `z`
directionally `g`-liftable for every `g`, because the explanation leaves no
cancellation coordinate at all. -/
theorem hasUnexplainedProximate_of_not_directionallyGLiftable
    {n k e m g : ℕ} {C : LinearCode F n} {u v : Word F n}
    (P : RSPresentation n k C) (D : DecoderData (e := e) (m := m) C u v)
    {z : F} (hz : z ∈ D.parameters)
    (hnot : ¬ DirectionallyGLiftable D z g) :
    HasUnexplainedProximate P.dom u v k e z := by
  obtain ⟨p, hpdeg, hpeq⟩ := P.exists_of_mem _ (D.codeword_mem hz)
  refine ⟨p, hpdeg, ?_, ?_⟩
  · -- The selected codeword is within the selection radius by construction.
    have hnear : weight (affineWord u v z - D.codeword z) ≤ e := by
      rw [D.codeword_eq hz]
      exact D.decoder_near ⟨z, hz⟩
    have hword : (fun x => u x + z * v x) = affineWord u v z := rfl
    rw [hword, ← hpeq, card_disagree_eq_weight_sub]
    exact hnear
  · -- An explaining pair would make `z` liftable, contradicting `hnot`.
    intro p₀ p₁ _ h₁ hexp
    refine hnot ⟨RSeval P.dom p₁, P.mem_of_natDegree_le p₁ h₁, ?_⟩
    have hempty : supportOn (selectedAgreementCoordinates D z)
        (v - RSeval P.dom p₁) = ∅ := by
      refine Finset.eq_empty_iff_forall_notMem.mpr ?_
      intro j hj
      rw [mem_supportOn] at hj
      obtain ⟨hjagree, hjsupport⟩ := hj
      rw [mem_selectedAgreementCoordinates] at hjagree
      have hline : u j + z * v j = p.eval (P.dom j) := by
        have := hjagree
        rw [hpeq] at this
        simpa [affineWord] using this
      exact hjsupport (by
        have := (hexp.2 j hline).2
        simp [Pi.sub_apply, RSeval, ← this])
    rw [hempty]
    simp

/-- **The Johnson-regime per-line bound.**  On a Reed–Solomon code presented at
degree `k`, the selected parameters that fail directional `g`-liftability number
fewer than `johnsonThreshold k n e η`, under exactly the numeric hypotheses of
`correlatedAgreement_johnson_final`.

This is the drop-in replacement for
`SelectedMCA.directionallyNonliftableParameters_card_le_direct`: same conclusion
shape, a different theorem paying for it. -/
theorem directionallyNonliftableParameters_card_lt_johnson
    {n k e m g : ℕ} {C : LinearCode F n} {u v : Word F n}
    (P : RSPresentation n k C) (D : DecoderData (e := e) (m := m) C u v) (η : ℝ)
    (hk1 : 1 ≤ k) (hη : 0 < η) (hη4 : η ≤ 1/4)
    (hηn : 1 ≤ η * n)
    (ht4 : 4 * η * n ≤ ((n - e : ℕ) : ℝ))
    (hJ : (k : ℝ) * n ≤ (((n - e : ℕ) : ℝ) - 4 * η * n) ^ 2)
    (_hfield : 9 * ((n : ℝ)) ^ 2 / (8 * k * η ^ 2) < Fintype.card F) :
    ((directionallyNonliftableParameters D g).card : ℝ) <
      johnsonThreshold k n e η := by
  classical
  have hcardfin : (Fintype.card (Fin n) : ℝ) = (n : ℝ) := by
    simp
  have hsub : directionallyNonliftableParameters D g ⊆
      Finset.univ.filter fun z => HasUnexplainedProximate P.dom u v k e z := by
    intro z hz
    obtain ⟨hzparam, hznot⟩ := Finset.mem_filter.mp hz
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
      hasUnexplainedProximate_of_not_directionallyGLiftable P D hzparam hznot⟩
  have hcard : ((directionallyNonliftableParameters D g).card : ℝ) ≤
      ((Finset.univ.filter fun z =>
        HasUnexplainedProximate P.dom u v k e z).card : ℝ) := by
    exact_mod_cast Finset.card_le_card hsub
  have hbad := strong_mutual_johnson P.dom P.dom_injective u v k e η hk1 hη hη4
    (by rwa [Fintype.card_fin]) (by rwa [Fintype.card_fin])
    (by rwa [Fintype.card_fin])
  rw [Fintype.card_fin] at hbad
  exact lt_of_le_of_lt hcard hbad

/-- **The Johnson-regime route to the per-line interface.**  A certificate
supplies a natural number `bound` dominating the threshold; the Johnson bound
then meets `SelectedMCA.LineFailureBound`, exactly as the clique condition does
through `SelectedMCA.lineFailureBound_of_directClique`.

`bound + 1` rather than `bound` on the right is what makes this a faithful
reading of the strict inequality: a certificate that rounds the threshold up to
an integer is admissible. -/
theorem lineFailureBound_of_johnson
    {n k e g bound : ℕ} {C : LinearCode F n}
    (P : RSPresentation n k C) (η : ℝ)
    (hk1 : 1 ≤ k) (hη : 0 < η) (hη4 : η ≤ 1/4)
    (hηn : 1 ≤ η * n)
    (ht4 : 4 * η * n ≤ ((n - e : ℕ) : ℝ))
    (hJ : (k : ℝ) * n ≤ (((n - e : ℕ) : ℝ) - 4 * η * n) ^ 2)
    (hfield : 9 * ((n : ℝ)) ^ 2 / (8 * k * η ^ 2) < Fintype.card F)
    (hbound : johnsonThreshold k n e η ≤ ((bound : ℝ) + 1)) :
    SelectedMCA.LineFailureBound C e g bound := by
  intro m u v D
  have hlt := directionallyNonliftableParameters_card_lt_johnson (g := g)
    P D η hk1 hη hη4 hηn ht4 hJ hfield
  have hreal : ((directionallyNonliftableParameters D g).card : ℝ) <
      (bound : ℝ) + 1 := lt_of_lt_of_le hlt hbound
  have hnat : (directionallyNonliftableParameters D g).card < bound + 1 := by
    exact_mod_cast hreal
  omega

end JBAgreement
