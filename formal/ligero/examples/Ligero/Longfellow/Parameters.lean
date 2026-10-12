import examples.Ligero.Longfellow.Soundness

set_option autoImplicit false
set_option relaxedAutoImplicit false
set_option warningAsError true

namespace Ligero.Examples.Grid.Rigid.Longfellow

inductive Component where
  | signature
  | hash
deriving DecidableEq

def Component.fieldSize : Component → ℕ
  | .signature => 2 ^ 256 - 2 ^ 224 + 2 ^ 192 + 2 ^ 96 - 1
  | .hash => 2 ^ 128

/-- Circuit metadata extracted from the registered, canonical-ID-checked artifacts. -/
structure RegisteredCircuit where
  version : ℕ
  attributes : ℕ
  component : Component
  bundleId : String
  circuitId : String
  blockEnc : ℕ
  rateInv : ℕ
  queries : ℕ
  ninputs : ℕ
  npublic : ℕ
  padSize : ℕ
  nlayers : ℕ
  nwrow : ℕ
  nqtriples : ℕ
  profile : CertifiedResult

def RegisteredCircuit.block (c : RegisteredCircuit) : ℕ :=
  (c.blockEnc + 1) / (2 + c.rateInv)

def RegisteredCircuit.columns (c : RegisteredCircuit) : ℕ :=
  c.blockEnc - (2 * c.block - 1)

def RegisteredCircuit.witnessWidth (c : RegisteredCircuit) : ℕ :=
  c.block - c.queries

/-- Bind every reported profile to the exact implementation layout and field order. -/
def RegisteredCircuit.Matches (c : RegisteredCircuit) : Prop :=
  (c.version = 6 ∨ c.version = 7) ∧
  c.profile.result.certificate.k = c.block ∧
  c.profile.result.certificate.n = c.columns ∧
  c.profile.result.certificate.d = c.columns - c.block + 1 ∧
  c.profile.result.certificate.fieldSize = c.component.fieldSize ∧
  c.profile.result.openings = c.queries ∧
  c.queries = (if c.version < 7 then 128 else 132) ∧
  c.rateInv = (if c.version < 7 then 4 else 7) ∧
  c.nwrow = (c.ninputs - c.npublic + c.padSize + c.witnessWidth - 1) /
    c.witnessWidth ∧
  c.nqtriples = (c.nlayers + c.witnessWidth - 1) / c.witnessWidth ∧
  0 < c.nwrow ∧
  c.queries ≤ c.witnessWidth ∧
  c.queries + c.witnessWidth + c.columns ≤ c.component.fieldSize

def RegisteredCircuit.matchesBool (c : RegisteredCircuit) : Bool :=
  @decide c.Matches (by unfold Matches; infer_instance)

/-- All four attribute counts for each of the two supported circuit versions,
with both component fields represented explicitly. -/
def registeredCircuits : List RegisteredCircuit := [
  { version := 7
    attributes := 1
    component := .signature
    bundleId := "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 4096
    rateInv := 7
    queries := 132
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 13
    nqtriples := 1
    profile := v7SigCertified },
  { version := 7
    attributes := 2
    component := .signature
    bundleId := "6a5810683e62b6d7766ebd0d7ca72518a2b8325418142adcadb10d51dbbcd5ad"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 4096
    rateInv := 7
    queries := 132
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 13
    nqtriples := 1
    profile := v7SigCertified },
  { version := 7
    attributes := 3
    component := .signature
    bundleId := "8ee4849ae1293ae6fe5f9082ce3e5e15c4f198f2998c682fa1b727237d6d252f"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 4096
    rateInv := 7
    queries := 132
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 13
    nqtriples := 1
    profile := v7SigCertified },
  { version := 7
    attributes := 4
    component := .signature
    bundleId := "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 4096
    rateInv := 7
    queries := 132
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 13
    nqtriples := 1
    profile := v7SigCertified },
  { version := 7
    attributes := 1
    component := .hash
    bundleId := "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"
    circuitId := "58248d20ded3b19b0996e478dda6afacba794fa2b1f0802771430bc0dca7d106"
    blockEnc := 4151
    rateInv := 7
    queries := 132
    ninputs := 85118
    npublic := 952
    padSize := 1183
    nlayers := 17
    nwrow := 260
    nqtriples := 1
    profile := v7Hash1Certified },
  { version := 7
    attributes := 2
    component := .hash
    bundleId := "6a5810683e62b6d7766ebd0d7ca72518a2b8325418142adcadb10d51dbbcd5ad"
    circuitId := "350806f428dafce638172976db598335c9a5399776a1bd08f177e569114b1b84"
    blockEnc := 4265
    rateInv := 7
    queries := 132
    ninputs := 90022
    npublic := 1736
    padSize := 1191
    nlayers := 17
    nwrow := 262
    nqtriples := 1
    profile := v7Hash2Certified },
  { version := 7
    attributes := 3
    component := .hash
    bundleId := "8ee4849ae1293ae6fe5f9082ce3e5e15c4f198f2998c682fa1b727237d6d252f"
    circuitId := "766f3cb1be33d346f3a0142e617504e524b3126daa8ec9fd0b131183eeb27d4b"
    blockEnc := 4307
    rateInv := 7
    queries := 132
    ninputs := 94926
    npublic := 2520
    padSize := 1199
    nlayers := 17
    nwrow := 271
    nqtriples := 1
    profile := v7Hash3Certified },
  { version := 7
    attributes := 4
    component := .hash
    bundleId := "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460"
    circuitId := "695247ca8691d1ac9c5c05280ce4b7cabeb803f8a9b597f03dd0d93ac0b21cb9"
    blockEnc := 4415
    rateInv := 7
    queries := 132
    ninputs := 99830
    npublic := 3304
    padSize := 1199
    nlayers := 17
    nwrow := 273
    nqtriples := 1
    profile := v7Hash4Certified },
  { version := 6
    attributes := 1
    component := .signature
    bundleId := "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 2945
    rateInv := 4
    queries := 128
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 11
    nqtriples := 1
    profile := v6SigCertified },
  { version := 6
    attributes := 2
    component := .signature
    bundleId := "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 2945
    rateInv := 4
    queries := 128
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 11
    nqtriples := 1
    profile := v6SigCertified },
  { version := 6
    attributes := 3
    component := .signature
    bundleId := "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 2945
    rateInv := 4
    queries := 128
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 11
    nqtriples := 1
    profile := v6SigCertified },
  { version := 6
    attributes := 4
    component := .signature
    bundleId := "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6"
    circuitId := "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d"
    blockEnc := 2945
    rateInv := 4
    queries := 128
    ninputs := 3739
    npublic := 900
    padSize := 1147
    nlayers := 21
    nwrow := 11
    nqtriples := 1
    profile := v6SigCertified },
  { version := 6
    attributes := 1
    component := .hash
    bundleId := "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"
    circuitId := "039bed19b94d5d732e1de555fa5c5c4b9b189b8c7908d3f1ee4ecb9e72f38532"
    blockEnc := 4096
    rateInv := 4
    queries := 128
    ninputs := 75098
    npublic := 944
    padSize := 1065
    nlayers := 15
    nwrow := 136
    nqtriples := 1
    profile := v6Hash1Certified },
  { version := 6
    attributes := 2
    component := .hash
    bundleId := "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e"
    circuitId := "998d8a96af09bdb7d66574c3375a649078b3fbf6cb863f8ba0407d3a3d73a0cd"
    blockEnc := 4025
    rateInv := 4
    queries := 128
    ninputs := 79902
    npublic := 1720
    padSize := 1069
    nlayers := 15
    nwrow := 146
    nqtriples := 1
    profile := v6Hash2Certified },
  { version := 6
    attributes := 3
    component := .hash
    bundleId := "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010"
    circuitId := "6fef452320934ed0cf63924b22a0ff3ec20771c7647b3950326305fff3908157"
    blockEnc := 4121
    rateInv := 4
    queries := 128
    ninputs := 84706
    npublic := 2496
    padSize := 1073
    nlayers := 15
    nwrow := 149
    nqtriples := 1
    profile := v6Hash3Certified },
  { version := 6
    attributes := 4
    component := .hash
    bundleId := "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6"
    circuitId := "2822c136eacd67fa250d300b1a3f5e090efcf8e4b0b2ace13c9d1b82f172e7d9"
    blockEnc := 4283
    rateInv := 4
    queries := 128
    ninputs := 89510
    npublic := 3272
    padSize := 1073
    nlayers := 15
    nwrow := 149
    nqtriples := 1
    profile := v6Hash4Certified }
]

theorem registered_circuit_count : registeredCircuits.length = 16 := by native_decide

theorem registered_layouts_checked :
    registeredCircuits.all RegisteredCircuit.matchesBool = true := by native_decide

theorem registered_matches {c : RegisteredCircuit}
    (hmem : c ∈ registeredCircuits) : c.Matches := by
  have h := registered_layouts_checked
  rw [List.all_eq_true] at h
  letI : Decidable c.Matches := by unfold RegisteredCircuit.Matches; infer_instance
  apply of_decide_eq_true
  simpa [RegisteredCircuit.matchesBool] using h c hmem


open LigeroFamily CodingTheory FirstOccurrenceEventLedger.TypedCounts

/-- Soundness for a registered circuit component, using its actual row
geometry, field order and opening count. All arithmetic and geometry
conditions are discharged by the checked catalog. -/
theorem RegisteredCircuit.end_to_end_soundness_sha256
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
      (N + 2) * ((1 : ℚ) / 2 ^ circuit.profile.result.certificate.targetBits) := by
  have hmatches := registered_matches hmem
  rcases hmatches with ⟨_hversion, hkMatch, _hn, _hd, horder,
    hqueries, _hqueryCount, _hrate, _hnw, _hnq, hnwPos, hwidth, _hcard⟩
  have hrows : CoreRowsNonempty circuit.nwrow circuit.nqtriples := Or.inl hnwPos
  have hqueryLe : circuit.queries ≤ circuit.block :=
    hwidth.trans (Nat.sub_le _ _)
  have hk : C.k = circuit.profile.result.certificate.k := by
    calc C.k = circuit.profile.result.openings + circuit.witnessWidth := C.k_eq
      _ = circuit.block := by
        rw [hqueries]
        unfold RegisteredCircuit.witnessWidth
        omega
      _ = circuit.profile.result.certificate.k := hkMatch.symm
  have hmodelField : Fintype.card F = circuit.profile.result.certificate.fieldSize :=
    hfield.trans horder.symm
  exact circuit.profile.end_to_end_soundness_sha256 hrows hmodelField C hk statement
    codec family dec hprefix adversary dflt alphaKey responseOf fallback hfalse hmin
    hDigest hMerkle

end Ligero.Examples.Grid.Rigid.Longfellow
