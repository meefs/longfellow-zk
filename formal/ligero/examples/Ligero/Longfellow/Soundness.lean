import examples.Ligero.Longfellow.Certificates

set_option autoImplicit false
set_option relaxedAutoImplicit false
set_option warningAsError true

namespace Ligero.Examples.Grid.Rigid.Longfellow

open LigeroFamily CodingTheory FirstOccurrenceEventLedger.TypedCounts

/-- Full finite-ROM V1 soundness, including binding failure and both
first-occurrence orders, with all numerical conditions supplied by a certificate. -/
theorem CertifiedResult.end_to_end_soundness
    (certificate : CertifiedResult)
    {F Equations Salt D Enc Output PrefixOut RunOut AlphaKey : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Inhabited Salt] [Inhabited D] [Fintype D]
    [DecidableEq D] [DecidableEq Enc] [DecidableEq AlphaKey]
    {w nw nq merkleT N prefixFuel runFuel : ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (hfield : Fintype.card F = certificate.result.certificate.fieldSize)
    (C : MultiplicativeCode F certificate.result.openings w certificate.result.certificate.n)
    (hk : C.k = certificate.result.certificate.k)
    (statement : ConstraintSystem F nw nq w Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F NoMask Ligero.V1.Mask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F nw nq 1 Equations)
          (QuerySet certificate.result.certificate.n certificate.result.openings))
      certificate.result.certificate.n merkleT prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec) (hprefix : prefixFuel ≤ merkleT)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey
        (AlphaKey × Response F certificate.result.openings w certificate.result.certificate.n 1))
      (Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F nw nq 1 Equations)
          (QuerySet certificate.result.certificate.n certificate.result.openings)) Output N)
    (dflt : Bcs.TypedFiatShamir.Answer
      (Ligero.V1.Challenge F nw nq 1 Equations)
        (QuerySet certificate.result.certificate.n certificate.result.openings))
    (alphaKey : AlphaKey)
    (responseOf : Output →
      Response F certificate.result.openings w certificate.result.certificate.n 1)
    (fallback : AlphaKey ×
      Response F certificate.result.openings w certificate.result.certificate.n 1)
    (hfalse : ¬statement.Language)
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode
      certificate.result.certificate.d) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _ ↦ alphaKey) (fun output ↦ (alphaKey, responseOf output))
    let win := fun merkleAnswers tape ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers))
          certificate.result.certificate.n ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C Ligero.V1.scheme).accepts statement alpha
            (responseOf output) query (fun j ↦ claim.a j.1)
    ((eventSet fun value :
        (Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F nw nq 1 Equations)
              (QuerySet certificate.result.certificate.n certificate.result.openings)) ↦
          win value.1 value.2).card : ℚ) /
        Fintype.card ((Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F nw nq 1 Equations)
              (QuerySet certificate.result.certificate.n certificate.result.openings))) ≤
      ((((prefixFuel * (prefixFuel - 1) / 2 +
            merkleT * (2 * prefixFuel + 1)) *
          Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
        Fintype.card (Fin merkleT → D)) +
      (N + 2) * ((1 : ℚ) / 2 ^ certificate.result.certificate.targetBits) := by
  exact certificate.result.v1_prefixBinding_ratio_le_of_bound
    certificate.parameters certificate.bound hrows hfield C hk statement
    codec family dec hprefix adversary dflt alphaKey responseOf fallback hfalse hmin

/-- The binding ledger for a 256-bit digest, with a nonempty oracle tape. -/
theorem merkleTerm_sha256 {D : Type*} [Fintype D]
    (merkleT prefixFuel : ℕ) (hMerkle : 0 < merkleT)
    (hDigest : Fintype.card D = 2 ^ 256) :
    ((((prefixFuel * (prefixFuel - 1) / 2 +
          merkleT * (2 * prefixFuel + 1)) *
        Fintype.card D ^ (merkleT - 1) : ℕ) : ℚ) /
      Fintype.card (Fin merkleT → D)) =
    ((prefixFuel * (prefixFuel - 1) / 2 +
        merkleT * (2 * prefixFuel + 1) : ℕ) : ℚ) / (2 : ℚ) ^ 256 := by
  simp only [Fintype.card_fun, Fintype.card_fin, hDigest,
    Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat]
  have hpow : ((2 : ℚ) ^ 256) ^ merkleT =
      ((2 : ℚ) ^ 256) ^ (merkleT - 1) * (2 : ℚ) ^ 256 := by
    conv_lhs => rw [show merkleT = merkleT - 1 + 1 from
      (Nat.sub_add_cancel hMerkle).symm]
    rw [pow_succ]
  rw [hpow]
  have hnonzero : ((2 : ℚ) ^ 256) ^ (merkleT - 1) ≠ 0 := by positivity
  field_simp [hnonzero]

/-- The certified V1 bound with Longfellow's digest length made explicit. -/
theorem CertifiedResult.end_to_end_soundness_sha256
    (certificate : CertifiedResult)
    {F Equations Salt D Enc Output PrefixOut RunOut AlphaKey : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Inhabited Salt] [Inhabited D] [Fintype D]
    [DecidableEq D] [DecidableEq Enc] [DecidableEq AlphaKey]
    {w nw nq merkleT N prefixFuel runFuel : ℕ}
    (hrows : CoreRowsNonempty nw nq)
    (hfield : Fintype.card F = certificate.result.certificate.fieldSize)
    (C : MultiplicativeCode F certificate.result.openings w certificate.result.certificate.n)
    (hk : C.k = certificate.result.certificate.k)
    (statement : ConstraintSystem F nw nq w Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F NoMask Ligero.V1.Mask nw nq 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F nw nq 1 Equations)
          (QuerySet certificate.result.certificate.n certificate.result.openings))
      certificate.result.certificate.n merkleT prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec) (hprefix : prefixFuel ≤ merkleT)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey
        (AlphaKey × Response F certificate.result.openings w certificate.result.certificate.n 1))
      (Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F nw nq 1 Equations)
          (QuerySet certificate.result.certificate.n certificate.result.openings)) Output N)
    (dflt : Bcs.TypedFiatShamir.Answer
      (Ligero.V1.Challenge F nw nq 1 Equations)
        (QuerySet certificate.result.certificate.n certificate.result.openings))
    (alphaKey : AlphaKey)
    (responseOf : Output →
      Response F certificate.result.openings w certificate.result.certificate.n 1)
    (fallback : AlphaKey ×
      Response F certificate.result.openings w certificate.result.certificate.n 1)
    (hfalse : ¬statement.Language)
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode
      certificate.result.certificate.d)
    (hDigest : Fintype.card D = 2 ^ 256)
    (hMerkle : 0 < merkleT) :
    let trace := Bcs.TypedFiatShamir.lazyFirstOccurrenceTrace N adversary
      dflt (fun _ ↦ alphaKey) (fun output ↦ (alphaKey, responseOf output))
    let win := fun merkleAnswers tape ↦
      let output := (Merkle.RandomOracle.lazyRun tape dflt adversary []).1
      let query := Bcs.TypedFiatShamir.definingSubsetAnswer trace tape
      let alpha := Bcs.TypedFiatShamir.definingAlphaAnswer trace tape
      let claim := (family.game tape).claim merkleAnswers
      claim.I = query.coordinates ∧
        Merkle.MH.Accepts
          (codec.withOracle ((family.game tape).oracle merkleAnswers))
          certificate.result.certificate.n ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C Ligero.V1.scheme).accepts statement alpha
            (responseOf output) query (fun j ↦ claim.a j.1)
    ((eventSet fun value :
        (Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F nw nq 1 Equations)
              (QuerySet certificate.result.certificate.n certificate.result.openings)) ↦
          win value.1 value.2).card : ℚ) /
        Fintype.card ((Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F nw nq 1 Equations)
              (QuerySet certificate.result.certificate.n certificate.result.openings))) ≤
      ((prefixFuel * (prefixFuel - 1) / 2 +
          merkleT * (2 * prefixFuel + 1) : ℕ) : ℚ) / (2 : ℚ) ^ 256 +
      (N + 2) * ((1 : ℚ) / 2 ^ certificate.result.certificate.targetBits) := by
  have h := certificate.end_to_end_soundness hrows hfield C hk statement
    codec family dec hprefix adversary dflt alphaKey responseOf fallback hfalse hmin
  dsimp only at h ⊢
  rw [merkleTerm_sha256 merkleT prefixFuel hMerkle hDigest] at h
  exact h

end Ligero.Examples.Grid.Rigid.Longfellow
