import Ligero.Common.Protocol.MaskScheme
import Mathlib.Data.Rat.Cast.Order

/-!
# Finite public-coin IPCP semantics for Ligero.Common

The committed oracle is fixed before the public challenge.  The response may
depend on that challenge, while the bounded column query is sampled only
afterwards and is unavailable to the prover.
-/

namespace Ligero.Common

/-- Acceptance probability of a Boolean verifier over a uniform finite tape. -/
def finiteProtocolAcceptanceRate
    {RandomTape : Type*} [Fintype RandomTape] [DecidableEq RandomTape]
    (accepts : RandomTape → Bool) : ℚ :=
  ((Finset.univ.filter fun randomness ↦ accepts randomness = true).card : ℚ) /
    Fintype.card RandomTape

/-- Uniform finite acceptance rates are invariant under a reindexing of the
random tape. -/
theorem finiteProtocolAcceptanceRate_eq_of_equiv
    {R₁ R₂ : Type*} [Fintype R₁] [Fintype R₂]
    [DecidableEq R₁] [DecidableEq R₂]
    (equivalence : R₁ ≃ R₂) (accepts₁ : R₁ → Bool) (accepts₂ : R₂ → Bool)
    (haccepts : ∀ randomness, accepts₁ randomness = accepts₂ (equivalence randomness)) :
    finiteProtocolAcceptanceRate accepts₁ =
      finiteProtocolAcceptanceRate accepts₂ := by
  classical
  have hcard : Fintype.card R₁ = Fintype.card R₂ :=
    Fintype.card_congr equivalence
  have hfilter :
      (Finset.univ.filter fun randomness ↦ accepts₁ randomness = true).card =
        (Finset.univ.filter fun randomness ↦ accepts₂ randomness = true).card := by
    apply Finset.card_bij (fun randomness _ ↦ equivalence randomness)
    · intro randomness hrandomness
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, by
        rw [← haccepts randomness]
        exact (Finset.mem_filter.mp hrandomness).2⟩
    · intro first _ second _ hequal
      exact equivalence.injective hequal
    · intro randomness hrandomness
      refine ⟨equivalence.symm randomness, ?_, equivalence.apply_symm_apply _⟩
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, by
        rw [haccepts, equivalence.apply_symm_apply]
        exact (Finset.mem_filter.mp hrandomness).2⟩
  unfold finiteProtocolAcceptanceRate
  rw [hfilter, hcard]

/-- A public-coin IPCP with one committed oracle and a later bounded opening. -/
structure PublicCoinIPCP
    (Statement Oracle Challenge Response Query : Type*)
    (Opening : Query → Type*) where
  language : Statement → Prop
  openOracle : (oracle : Oracle) → (query : Query) → Opening query
  verify : Statement → Challenge → Response →
    (query : Query) → Opening query → Bool

/-- A malicious prover commits before seeing the challenge and responds before
seeing the later query. -/
structure IPCPProver
    (Statement Oracle Challenge Response : Type*) where
  commit : Statement → Oracle
  respond : Statement → Oracle → Challenge → Response

structure IPCPTranscript
    (Oracle Challenge Response Query : Type*) (Opening : Query → Type*) where
  oracle : Oracle
  challenge : Challenge
  response : Response
  query : Query
  opening : Opening query

structure IPCPVerifierView
    (Challenge Response Query : Type*) (Opening : Query → Type*) where
  challenge : Challenge
  response : Response
  query : Query
  opening : Opening query

namespace PublicCoinIPCP

variable {Statement Oracle Challenge Response Query : Type*}
variable {Opening : Query → Type*}

def run
    (protocol : PublicCoinIPCP Statement Oracle Challenge Response Query Opening)
    (prover : IPCPProver Statement Oracle Challenge Response)
    (statement : Statement) (coins : Challenge × Query) :
    IPCPTranscript Oracle Challenge Response Query Opening :=
  let oracle := prover.commit statement
  let response := prover.respond statement oracle coins.1
  { oracle
    challenge := coins.1
    response
    query := coins.2
    opening := protocol.openOracle oracle coins.2 }

def verifierView
    (protocol : PublicCoinIPCP Statement Oracle Challenge Response Query Opening)
    (prover : IPCPProver Statement Oracle Challenge Response)
    (statement : Statement) (coins : Challenge × Query) :
    IPCPVerifierView Challenge Response Query Opening :=
  let transcript := protocol.run prover statement coins
  { challenge := transcript.challenge
    response := transcript.response
    query := transcript.query
    opening := transcript.opening }

def accepts
    (protocol : PublicCoinIPCP Statement Oracle Challenge Response Query Opening)
    (prover : IPCPProver Statement Oracle Challenge Response)
    (statement : Statement) (coins : Challenge × Query) : Bool :=
  let transcript := protocol.run prover statement coins
  protocol.verify statement transcript.challenge transcript.response
    transcript.query transcript.opening

def acceptanceRate
    [Fintype Challenge] [DecidableEq Challenge]
    [Fintype Query] [DecidableEq Query]
    (protocol : PublicCoinIPCP Statement Oracle Challenge Response Query Opening)
    (prover : IPCPProver Statement Oracle Challenge Response)
    (statement : Statement) : ℚ :=
  finiteProtocolAcceptanceRate (protocol.accepts prover statement)

def SoundnessAtMost
    [Fintype Challenge] [DecidableEq Challenge]
    [Fintype Query] [DecidableEq Query]
    [Nonempty Challenge] [Nonempty Query]
    (protocol : PublicCoinIPCP Statement Oracle Challenge Response Query Opening)
    (error : ℚ) : Prop :=
  ∀ statement, ¬ protocol.language statement →
    ∀ prover, protocol.acceptanceRate prover statement ≤ error

def PerfectCompleteness
    (protocol : PublicCoinIPCP Statement Oracle Challenge Response Query Opening)
    {Witness : Type*} (relation : Statement → Witness → Prop)
    (honestProver : Witness → IPCPProver Statement Oracle Challenge Response) : Prop :=
  ∀ statement witness, relation statement witness →
    ∀ coins, protocol.accepts (honestProver witness) statement coins = true

end PublicCoinIPCP

namespace Verifier

variable {F Equations : Type*} [Field F] [Fintype Equations]
variable {r w n nw nq repetitions : ℕ}

/-- The corrected evaluation-space verifier as a finite public-coin IPCP. -/
noncomputable def protocol
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis) :
    PublicCoinIPCP
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n repetitions)
      (Challenge F nw nq repetitions Equations)
      (Response F r w n repetitions)
      (QuerySet n r)
      (Opening F nw nq repetitions n r) where
  language := ConstraintSystem.Language
  openOracle := Ligero.Common.openOracle
  verify statement challenge response query opening :=
    by
      classical
      exact decide (Accepts C M statement challenge response query opening)

end Verifier

namespace SchemeVerifier

variable {F Equations CheckedMask DirectMask : Type*}
variable [Field F] [Fintype Equations] [Fintype CheckedMask]
variable {r w n nw nq repetitions : ℕ}



noncomputable def protocol
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n) :
    PublicCoinIPCP
      (ConstraintSystem F nw nq w Equations)
      (SchemeOracle F CheckedMask DirectMask nw nq n repetitions)
      (SchemeChallenge F CheckedMask nw nq repetitions Equations)
      (Response F r w n repetitions)
      (QuerySet n r)
      (SchemeOpening F CheckedMask DirectMask nw nq repetitions n r) where
  language := ConstraintSystem.Language
  openOracle := openSchemeOracle
  verify statement challenge response query opening := by
    classical
    exact decide (Accepts C scheme statement challenge response query opening)

end SchemeVerifier

namespace IPCPProver



def asCheckedScheme
    {F Equations : Type*} {r w n nw nq repetitions : ℕ}
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n repetitions)
      (Challenge F nw nq repetitions Equations)
      (Response F r w n repetitions)) :
    IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (SchemeOracle F ConstraintMask NoMask nw nq n repetitions)
      (SchemeChallenge F ConstraintMask nw nq repetitions Equations)
      (Response F r w n repetitions) where
  commit statement := (prover.commit statement).asScheme
  respond statement oracle challenge :=
    prover.respond statement
      {
        core := oracle.core
        mask := oracle.checkedMask
        proximityBlind := oracle.proximityBlind }
      (schemeChallengeAsChecked challenge)

end IPCPProver



theorem checked_protocol_acceptanceRate_eq
    {F Equations : Type*} [Field F] [Fintype F] [DecidableEq F]
    [Fintype Equations] [DecidableEq Equations]
    {r w n nw nq : ℕ}
    (C : MultiplicativeCode F r w n) (M : C.MaskingBasis)
    (prover : IPCPProver
      (ConstraintSystem F nw nq w Equations)
      (Oracle F nw nq n 1)
      (Challenge F nw nq 1 Equations)
      (Response F r w n 1))
    (statement : ConstraintSystem F nw nq w Equations) :
    (Verifier.protocol C M).acceptanceRate prover statement =
      (SchemeVerifier.protocol C (MaskScheme.checked C M)).acceptanceRate
        prover.asCheckedScheme statement := by
  classical
  let coinEquiv :
      (Challenge F nw nq 1 Equations × QuerySet n r) ≃
        (SchemeChallenge F ConstraintMask nw nq 1 Equations ×
          QuerySet n r) :=
    Equiv.prodCongr
      (checkedChallengeEquiv F Equations nw nq 1) (Equiv.refl _)
  unfold PublicCoinIPCP.acceptanceRate
  apply finiteProtocolAcceptanceRate_eq_of_equiv coinEquiv
  intro coins
  simp only [PublicCoinIPCP.accepts, PublicCoinIPCP.run, Verifier.protocol,
    SchemeVerifier.protocol, coinEquiv, Equiv.prodCongr_apply,
    checkedChallengeEquiv, IPCPProver.asCheckedScheme, decide_eq_decide]
  rw [openOracle_asScheme]
  change Verifier.Accepts C M statement coins.1
      (prover.respond statement (prover.commit statement) coins.1) coins.2
        (openOracle (prover.commit statement) coins.2) ↔
    SchemeVerifier.Accepts C (MaskScheme.checked C M) statement
      (challengeAsScheme coins.1)
      (prover.respond statement (prover.commit statement) coins.1) coins.2
        (openOracle (prover.commit statement) coins.2).asScheme
  exact (checked_accepts_iff C M statement coins.1
    (prover.respond statement (prover.commit statement) coins.1) coins.2
      (openOracle (prover.commit statement) coins.2)).symm

end Ligero.Common
