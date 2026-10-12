import examples.Ligero.Longfellow.Parameters

set_option autoImplicit false
set_option relaxedAutoImplicit false
set_option warningAsError true

namespace Ligero.Examples.Grid.Rigid.Longfellow

/-- The certified V7 coefficient, before the Fiat--Shamir query factor
and the Merkle binding term. -/
def Component.soundnessBits : Component → ℕ
  | .signature => 122
  | .hash => 121

/-- Every registered V7 component has the claimed coefficient. -/
theorem registered_soundness_bits_checked :
    registeredCircuits.all (fun c => decide
      (c.profile.result.certificate.targetBits = c.component.soundnessBits)) = true := by
  native_decide

theorem registered_soundness_bits {c : RegisteredCircuit}
    (hmem : c ∈ registeredCircuits) :
    c.profile.result.certificate.targetBits = c.component.soundnessBits := by
  have h := registered_soundness_bits_checked
  rw [List.all_eq_true] at h
  exact of_decide_eq_true (h c hmem)

open LigeroFamily CodingTheory FirstOccurrenceEventLedger.TypedCounts

/-- V7 top-level finite-ROM soundness for each registered component:
122-bit signature and 121-bit hash coefficients, with the explicit query
factor and Merkle binding error. The event and hypotheses are those of the
formal V1 verifier; implementation refinement and mdoc composition are separate. -/
theorem RegisteredCircuit.v7_soundness
    (circuit : RegisteredCircuit) (hmem : circuit ∈ registeredCircuits)
    {F Equations Salt D Enc Output PrefixOut RunOut AlphaKey : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    [Inhabited Salt] [Inhabited D] [Fintype D]
    [DecidableEq D] [DecidableEq Enc] [DecidableEq AlphaKey]
    {merkleT N prefixFuel runFuel : ℕ}
    (hfield : Fintype.card F = circuit.component.fieldSize)
    (C : MultiplicativeCode F circuit.profile.result.openings circuit.witnessWidth circuit.profile.result.certificate.n)
    (statement : ConstraintSystem F circuit.nwrow circuit.nqtriples circuit.witnessWidth Equations)
    (codec : Merkle.MH.Codec Salt
      (SchemeColumn F NoMask Ligero.V1.Mask circuit.nwrow circuit.nqtriples 1) D Enc)
    (family : Merkle.MH.PrefixBindingFamily
      (Out := PrefixOut) (RunOut := RunOut) codec
      (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F circuit.nwrow circuit.nqtriples 1 Equations)
          (QuerySet circuit.profile.result.certificate.n circuit.profile.result.openings))
      circuit.profile.result.certificate.n merkleT prefixFuel runFuel)
    (dec : Merkle.MH.RoleDecoders codec) (hprefix : prefixFuel ≤ merkleT)
    (adversary : Merkle.RandomOracle.Tree
      (Bcs.TypedFiatShamir.Query AlphaKey
        (AlphaKey × Response F circuit.profile.result.openings circuit.witnessWidth circuit.profile.result.certificate.n 1))
      (Bcs.TypedFiatShamir.Answer
        (Ligero.V1.Challenge F circuit.nwrow circuit.nqtriples 1 Equations)
          (QuerySet circuit.profile.result.certificate.n circuit.profile.result.openings)) Output N)
    (dflt : Bcs.TypedFiatShamir.Answer
      (Ligero.V1.Challenge F circuit.nwrow circuit.nqtriples 1 Equations)
        (QuerySet circuit.profile.result.certificate.n circuit.profile.result.openings))
    (alphaKey : AlphaKey)
    (responseOf : Output →
      Response F circuit.profile.result.openings circuit.witnessWidth circuit.profile.result.certificate.n 1)
    (fallback : AlphaKey ×
      Response F circuit.profile.result.openings circuit.witnessWidth circuit.profile.result.certificate.n 1)
    (hfalse : ¬statement.Language)
    (hmin : CodingTheory.HasMinimumDistanceAtLeast C.baseCode
      circuit.profile.result.certificate.d)
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
          circuit.profile.result.certificate.n ((family.game tape).root merkleAnswers)
          claim.I claim.a claim.pf ∧
        (SchemeVerifier.policy (Equations := Equations) (nw := circuit.nwrow) (nq := circuit.nqtriples)
          (repetitions := 1) C Ligero.V1.scheme).accepts statement alpha
            (responseOf output) query (fun j ↦ claim.a j.1)
    ((eventSet fun value :
        (Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F circuit.nwrow circuit.nqtriples 1 Equations)
              (QuerySet circuit.profile.result.certificate.n circuit.profile.result.openings)) ↦
          win value.1 value.2).card : ℚ) /
        Fintype.card ((Fin merkleT → D) ×
          (Fin (N + 2) → Bcs.TypedFiatShamir.Answer
            (Ligero.V1.Challenge F circuit.nwrow circuit.nqtriples 1 Equations)
              (QuerySet circuit.profile.result.certificate.n circuit.profile.result.openings))) ≤
      ((prefixFuel * (prefixFuel - 1) / 2 +
          merkleT * (2 * prefixFuel + 1) : ℕ) : ℚ) / (2 : ℚ) ^ 256 +
      (N + 2) * ((1 : ℚ) / 2 ^ circuit.component.soundnessBits) := by
  have h := circuit.end_to_end_soundness_sha256 hmem hfield C statement
    codec family dec hprefix adversary dflt alphaKey responseOf fallback
    hfalse hmin hDigest hMerkle
  simpa only [registered_soundness_bits hmem] using h

end Ligero.Examples.Grid.Rigid.Longfellow
