import Ligero.Common.Protocol.HonestCore
import Ligero.Common.Protocol.MaskScheme










namespace Ligero.MaskV1

open Ligero.Common

open MultiplicativeCode

variable {F Equations : Type*} [Field F] [Fintype Equations]
variable {r w n nw nq repetitions : ℕ}

/-- Honest private data for V1, expressed with the common evaluation
rows.  Direct masks satisfy exactly the global conditions needed by the two
arithmetic responses. -/
structure V1HonestEncoding
    (C : MultiplicativeCode F r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (messages : CoreMessages F nw nq w) where
  core : (block : CoreBlock) → Fin (block.rowCount nw nq) →
    EvaluationRow F r w n
  core_mem : ∀ block row, core block row ∈ C.base
  core_witness : ∀ block row i,
    core block row (witnessPosition i) = messages block row i
  linearMask : Fin repetitions → EvaluationRow F r w n
  linearMask_mem : ∀ h, linearMask h ∈ C.response
  linearMask_sum : ∀ h,
    ∑ i : Fin w, linearMask h (witnessPosition i) = 0
  quadraticMask : Fin repetitions → EvaluationRow F r w n
  quadraticMask_mem : ∀ h, quadraticMask h ∈ C.response
  quadraticMask_zero : ∀ h i,
    quadraticMask h (witnessPosition i) = 0
  proximityBlind : Fin repetitions → EvaluationRow F r w n
  proximityBlind_mem : ∀ h, proximityBlind h ∈ C.base
  satisfies : statement.Satisfies messages

namespace V1HonestEncoding

variable {C : MultiplicativeCode F r w n}
variable {statement : ConstraintSystem F nw nq w Equations}
variable {messages : CoreMessages F nw nq w}

/-- Forget the V1 mask representation and retain the shared honest
core used by both protocol versions. -/
def honestCore
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages) : HonestCore C statement messages where
  row := encoding.core
  row_mem := encoding.core_mem
  row_witness := encoding.core_witness
  satisfies := encoding.satisfies

def oracle
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages) :
    SchemeOracle F NoMask V1Mask nw nq n repetitions where
  core block row j := encoding.core block row (codePosition j)
  checkedMask _ impossible := NoMask.elim impossible
  directMask h kind j := match kind with
    | .linear => encoding.linearMask h (codePosition j)
    | .quadratic => encoding.quadraticMask h (codePosition j)
  proximityBlind h j := encoding.proximityBlind h (codePosition j)

noncomputable def proximityResponse
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (h : Fin repetitions) : EvaluationRow F r w n :=
  (∑ row : SchemeTestedRow NoMask nw nq repetitions,
      (challenge h).proximity row • match row with
        | Sum.inl core => encoding.core core.1 core.2
        | Sum.inr impossible => NoMask.elim impossible.2) +
    encoding.proximityBlind h

noncomputable def linearResponse
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (h : Fin repetitions) : EvaluationRow F r w n :=
  Verifier.linearCore C statement (challenge h).linear encoding.core +
    encoding.linearMask h

noncomputable def quadraticResponse
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (h : Fin repetitions) : EvaluationRow F r w n :=
  Verifier.quadraticCore (challenge h).quadratic encoding.core +
    encoding.quadraticMask h

noncomputable def response
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations) :
    Response F r w n repetitions where
  proximity h := encoding.proximityResponse challenge h
  linear h := encoding.linearResponse challenge h
  quadratic h := encoding.quadraticResponse challenge h

noncomputable def prover
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages) :
    IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (SchemeOracle F NoMask V1Mask nw nq n repetitions)
      (SchemeChallenge F NoMask nw nq repetitions Equations)
      (Response F r w n repetitions) where
  commit _ := encoding.oracle
  respond _ _ challenge := encoding.response challenge

omit [Fintype Equations] in
theorem proximityResponse_mem
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (h : Fin repetitions) : encoding.proximityResponse challenge h ∈ C.base := by
  apply C.base.add_mem
  · apply Submodule.sum_mem
    intro row _
    cases row with
    | inl core => exact C.base.smul_mem _ (encoding.core_mem core.1 core.2)
    | inr impossible => exact NoMask.elim impossible.2
  · exact encoding.proximityBlind_mem h

theorem linearResponse_mem
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (h : Fin repetitions) : encoding.linearResponse challenge h ∈ C.response := by
  apply C.response.add_mem
  · exact encoding.honestCore.linearResponse_mem (challenge h).linear
  · exact encoding.linearMask_mem h

omit [Fintype Equations] in
theorem quadraticResponse_mem
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (h : Fin repetitions) : encoding.quadraticResponse challenge h ∈ C.response := by
  apply C.response.add_mem
  · exact encoding.honestCore.quadraticResponse_mem (challenge h).quadratic
  · exact encoding.quadraticMask_mem h

theorem proximity_accepts
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (query : QuerySet n r) (h : Fin repetitions) :
    SchemeVerifier.ProximityAccepts C (challenge h).proximity
      ((encoding.response challenge).proximity h) query
      (openSchemeOracle encoding.oracle query) h := by
  refine ⟨encoding.proximityResponse_mem challenge h, ?_⟩
  intro j
  simp [response, proximityResponse, openSchemeOracle, oracle,
    SchemeOracle.column, Finset.sum_apply]

theorem linear_accepts
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (query : QuerySet n r) (h : Fin repetitions) :
    SchemeVerifier.LinearAccepts C MaskScheme.v1 statement
      (challenge h).linear ((encoding.response challenge).linear h) query
      (openSchemeOracle encoding.oracle query) h := by
  refine ⟨encoding.linearResponse_mem challenge h, ?_, ?_⟩
  · simp only [response, linearResponse, Pi.add_apply, Finset.sum_add_distrib]
    have hcore := encoding.honestCore.linearResponse_sum (challenge h).linear
    simp only [honestCore, HonestCore.linearResponse] at hcore
    rw [hcore, encoding.linearMask_sum h, add_zero]
  · intro j
    simp [response, linearResponse, Verifier.linearCore,
      MaskScheme.v1, openSchemeOracle, oracle, SchemeOracle.column,
      Finset.sum_apply]

theorem quadratic_accepts
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (query : QuerySet n r) (h : Fin repetitions) :
    SchemeVerifier.QuadraticAccepts C MaskScheme.v1
      (challenge h).quadratic ((encoding.response challenge).quadratic h) query
      (openSchemeOracle encoding.oracle query) h := by
  refine ⟨encoding.quadraticResponse_mem challenge h, ?_, ?_⟩
  · intro i
    have hcore := encoding.honestCore.quadraticResponse_witness
      (challenge h).quadratic i
    simp only [honestCore, HonestCore.quadraticResponse] at hcore
    simp only [response, quadraticResponse, Pi.add_apply]
    rw [hcore, encoding.quadraticMask_zero h i, add_zero]
  · intro j
    simp [response, quadraticResponse, Verifier.quadraticCore,
      MaskScheme.v1, openSchemeOracle, oracle, SchemeOracle.column,
      Finset.sum_apply]

/-- Perfect completeness of V1 in the common architecture. -/
theorem accepts
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (challenge : SchemeChallenge F NoMask nw nq repetitions Equations)
    (query : QuerySet n r) :
    SchemeVerifier.Accepts C MaskScheme.v1 statement challenge
      (encoding.response challenge) query
      (openSchemeOracle encoding.oracle query) := by
  intro h
  exact ⟨encoding.proximity_accepts challenge query h,
    encoding.linear_accepts challenge query h,
    encoding.quadratic_accepts challenge query h⟩

theorem protocol_accepts
    (encoding : V1HonestEncoding (repetitions := repetitions)
      C statement messages)
    (coins : SchemeChallenge F NoMask nw nq repetitions Equations × QuerySet n r) :
    (SchemeVerifier.protocol C MaskScheme.v1).accepts encoding.prover
      statement coins = true := by
  simp only [PublicCoinIPCP.accepts, PublicCoinIPCP.run,
    SchemeVerifier.protocol, decide_eq_true_eq]
  exact encoding.accepts coins.1 coins.2

end V1HonestEncoding

/-- Direct linear masks are response rows with zero witness-coordinate sum. -/
def V1LinearMaskSpace (C : MultiplicativeCode F r w n) :
    Submodule F (EvaluationRow F r w n) where
  carrier := { row | row ∈ C.response ∧
    ∑ i : Fin w, row (witnessPosition i) = 0 }
  zero_mem' := by simp
  add_mem' := by
    rintro left right ⟨hleft, hleftSum⟩ ⟨hright, hrightSum⟩
    refine ⟨C.response.add_mem hleft hright, ?_⟩
    simp only [Pi.add_apply, Finset.sum_add_distrib, hleftSum, hrightSum,
      add_zero]
  smul_mem' := by
    rintro scalar row ⟨hrow, hsum⟩
    refine ⟨C.response.smul_mem scalar hrow, ?_⟩
    simp only [Pi.smul_apply, smul_eq_mul, ← Finset.mul_sum, hsum, mul_zero]

/-- Direct quadratic masks are response rows vanishing at every witness
coordinate. -/
def V1QuadraticMaskSpace (C : MultiplicativeCode F r w n) :
    Submodule F (EvaluationRow F r w n) where
  carrier := { row | row ∈ C.response ∧
    ∀ i : Fin w, row (witnessPosition i) = 0 }
  zero_mem' := by simp
  add_mem' := by
    rintro left right ⟨hleft, hleftZero⟩ ⟨hright, hrightZero⟩
    refine ⟨C.response.add_mem hleft hright, ?_⟩
    intro i
    simp [hleftZero i, hrightZero i]
  smul_mem' := by
    rintro scalar row ⟨hrow, hzero⟩
    refine ⟨C.response.smul_mem scalar hrow, ?_⟩
    intro i
    simp [hzero i]

/-- V1's private tape on the common row model. -/
structure V1ProverRandomness
    (C : MultiplicativeCode F r w n) (nw nq repetitions : ℕ) where
  corePadding : (block : CoreBlock) →
    Fin (block.rowCount nw nq) → Fin r → F
  linearMask : Fin repetitions → V1LinearMaskSpace C
  quadraticMask : Fin repetitions → V1QuadraticMaskSpace C
  proximityBlind : Fin repetitions → C.base

def v1ProverRandomnessEquiv
    (C : MultiplicativeCode F r w n) (nw nq repetitions : ℕ) :
    V1ProverRandomness C nw nq repetitions ≃
      ((block : CoreBlock) → Fin (block.rowCount nw nq) → Fin r → F) ×
      (Fin repetitions → V1LinearMaskSpace C) ×
      (Fin repetitions → V1QuadraticMaskSpace C) ×
      (Fin repetitions → C.base) where
  toFun seed := (seed.corePadding, seed.linearMask, seed.quadraticMask,
    seed.proximityBlind)
  invFun fields := {
    corePadding := fields.1
    linearMask := fields.2.1
    quadraticMask := fields.2.2.1
    proximityBlind := fields.2.2.2 }
  left_inv seed := by cases seed; rfl
  right_inv fields := by rcases fields with ⟨core, linear, quadratic, blind⟩; rfl

/-- V1 prover tapes are finite, so quantification over a tape is the exact
uniform finite distribution used by the privacy theorems. -/
noncomputable instance v1ProverRandomnessFintype
    [Fintype F] (C : MultiplicativeCode F r w n) :
    Fintype (V1ProverRandomness C nw nq repetitions) := by
  letI : Fintype (V1LinearMaskSpace C) := Fintype.ofFinite _
  letI : Fintype (V1QuadraticMaskSpace C) := Fintype.ofFinite _
  letI : Fintype C.base := Fintype.ofFinite _
  exact Fintype.ofEquiv
    (((block : CoreBlock) → Fin (block.rowCount nw nq) → Fin r → F) ×
      (Fin repetitions → V1LinearMaskSpace C) ×
      (Fin repetitions → V1QuadraticMaskSpace C) ×
      (Fin repetitions → C.base))
    (v1ProverRandomnessEquiv C nw nq repetitions).symm

namespace V1ProverRandomness

variable {C : MultiplicativeCode F r w n}
variable {statement : ConstraintSystem F nw nq w Equations}

/-- Deterministically instantiate the V1 protocol from a satisfying
witness and a private tape. -/
noncomputable def encoding
    (messages : CoreMessages F nw nq w)
    (hsatisfies : statement.Satisfies messages)
    (seed : V1ProverRandomness C nw nq repetitions) :
    V1HonestEncoding (repetitions := repetitions) C statement messages where
  core block row := C.encode (seed.corePadding block row) (messages block row)
  core_mem _ _ := C.encode_mem _ _
  core_witness _ _ i := C.encode_witness _ _ i
  linearMask h := seed.linearMask h
  linearMask_mem h := (seed.linearMask h).2.1
  linearMask_sum h := (seed.linearMask h).2.2
  quadraticMask h := seed.quadraticMask h
  quadraticMask_mem h := (seed.quadraticMask h).2.1
  quadraticMask_zero h := (seed.quadraticMask h).2.2
  proximityBlind h := seed.proximityBlind h
  proximityBlind_mem h := (seed.proximityBlind h).2
  satisfies := hsatisfies

noncomputable def prover
    (messages : CoreMessages F nw nq w)
    (hsatisfies : statement.Satisfies messages)
    (seed : V1ProverRandomness C nw nq repetitions) :
    IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (SchemeOracle F NoMask V1Mask nw nq n repetitions)
      (SchemeChallenge F NoMask nw nq repetitions Equations)
      (Response F r w n repetitions) :=
  (seed.encoding messages hsatisfies).prover

end V1ProverRandomness



theorem v1_ligero_perfect_completeness
    {C : MultiplicativeCode F r w n}
    {statement : ConstraintSystem F nw nq w Equations}
    (messages : CoreMessages F nw nq w)
    (hsatisfies : statement.Satisfies messages)
    (seed : V1ProverRandomness C nw nq repetitions)
    (coins : SchemeChallenge F NoMask nw nq repetitions Equations × QuerySet n r) :
    (SchemeVerifier.protocol C MaskScheme.v1).accepts
      (seed.prover messages hsatisfies) statement coins = true :=
  (seed.encoding messages hsatisfies).protocol_accepts coins

end Ligero.MaskV1
