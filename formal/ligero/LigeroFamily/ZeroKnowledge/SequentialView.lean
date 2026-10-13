import LigeroFamily.Protocol.Sequential
import LigeroFamily.ZeroKnowledge.Distribution

/-! # Sequential response-adaptive verifier views -/

namespace LigeroFamily.ZeroKnowledge

open LigeroFamily

/-- A malicious verifier that chooses the second challenge after the first
response and the bounded query after the second response. -/
structure SequentialResponseAdaptiveVerifier
    (Coins FirstChallenge FirstResponse SecondChallenge SecondResponse Query :
      Type*) where
  firstChallenge : Coins → FirstChallenge
  secondChallenge : Coins → FirstResponse → SecondChallenge
  query : Coins → FirstResponse → SecondResponse → Query

structure SequentialResponseAdaptiveView
    (Coins FirstChallenge FirstResponse SecondChallenge SecondResponse Query :
      Type*) (Opening : Query → Type*) where
  verifierCoins : Coins
  firstChallenge : FirstChallenge
  firstResponse : FirstResponse
  secondChallenge : SecondChallenge
  secondResponse : SecondResponse
  query : Query
  opening : Opening query

variable {Statement Oracle FirstChallenge FirstResponse SecondChallenge
  SecondResponse Query Coins : Type*}
variable {Opening : Query → Type*}

def sequentialResponseAdaptiveView
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (prover : SequentialIPCPProver Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse)
    (statement : Statement)
    (verifier : SequentialResponseAdaptiveVerifier Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query)
    (coins : Coins) : SequentialResponseAdaptiveView Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening :=
  let oracle := prover.commit statement
  let firstChallenge := verifier.firstChallenge coins
  let firstResponse := prover.firstRespond statement oracle firstChallenge
  let secondChallenge := verifier.secondChallenge coins firstResponse
  let secondResponse := prover.secondRespond statement oracle firstChallenge
    firstResponse secondChallenge
  let query := verifier.query coins firstResponse secondResponse
  { verifierCoins := coins
    firstChallenge
    firstResponse
    secondChallenge
    secondResponse
    query
    opening := protocol.openOracle oracle query }

def randomizedSequentialView
    {Witness Tape : Type*}
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (honestProver : Statement → Witness → Tape →
      SequentialIPCPProver Statement Oracle FirstChallenge FirstResponse
        SecondChallenge SecondResponse)
    (statement : Statement) (witness : Witness)
    (verifier : SequentialResponseAdaptiveVerifier Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query)
    (randomness : Tape × Coins) :=
  sequentialResponseAdaptiveView protocol
    (honestProver statement witness randomness.1) statement verifier randomness.2

def UnboundedPerfectSequentialZeroKnowledgeAgainst
    {Witness Tape SimulatorTape : Type*}
    [Fintype Tape] [Fintype Coins] [Fintype SimulatorTape]
    [DecidableEq (SequentialResponseAdaptiveView Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)]
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (relation : Statement → Witness → Prop)
    (honestProver : Statement → Witness → Tape →
      SequentialIPCPProver Statement Oracle FirstChallenge FirstResponse
        SecondChallenge SecondResponse)
    (verifier : SequentialResponseAdaptiveVerifier Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query)
    (simulator : Statement → SimulatorTape →
      SequentialResponseAdaptiveView Coins FirstChallenge FirstResponse
        SecondChallenge SecondResponse Query Opening) : Prop :=
  ∀ statement witness, relation statement witness →
    SameDistribution
      (randomizedSequentialView protocol honestProver statement witness verifier)
      (simulator statement)

/-- Exact zero knowledge against every finite sequential response-adaptive
verifier.  The verifier may choose its second challenge after the first
response and its bounded query after the second response.  As with the
single-verifier definition above, the simulator is information-theoretic and
need not be computable. -/
def UnboundedPerfectSequentialZeroKnowledge
    {Witness Tape SimulatorTape : Type*}
    [Fintype Tape] [Fintype Coins] [Fintype SimulatorTape]
    [DecidableEq (SequentialResponseAdaptiveView Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)]
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (relation : Statement → Witness → Prop)
    (honestProver : Statement → Witness → Tape →
      SequentialIPCPProver Statement Oracle FirstChallenge FirstResponse
        SecondChallenge SecondResponse)
    (simulator : SequentialResponseAdaptiveVerifier Coins FirstChallenge
        FirstResponse SecondChallenge SecondResponse Query →
      Statement → SimulatorTape →
        SequentialResponseAdaptiveView Coins FirstChallenge FirstResponse
          SecondChallenge SecondResponse Query Opening) : Prop :=
  ∀ verifier, UnboundedPerfectSequentialZeroKnowledgeAgainst protocol relation
    honestProver verifier (simulator verifier)

section TapeTranslation

variable {Tape View : Type*}

def sequentialTapeTranslate
    (verifier : SequentialResponseAdaptiveVerifier Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query)
    (firstResponse : Tape → FirstChallenge → FirstResponse)
    (secondResponse : Tape → FirstChallenge → SecondChallenge →
      SecondResponse)
    (translate : Query → FirstChallenge → SecondChallenge → Tape →
      Tape)
    (randomness : Tape × Coins) : Tape × Coins :=
  let firstChallenge := verifier.firstChallenge randomness.2
  let first := firstResponse randomness.1 firstChallenge
  let secondChallenge := verifier.secondChallenge randomness.2 first
  let second := secondResponse randomness.1 firstChallenge secondChallenge
  let query := verifier.query randomness.2 first second
  (translate query firstChallenge secondChallenge randomness.1, randomness.2)

theorem sequentialTapeTranslate_injective
    (verifier : SequentialResponseAdaptiveVerifier Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query)
    (firstFrom firstTo : Tape → FirstChallenge → FirstResponse)
    (secondFrom secondTo : Tape → FirstChallenge → SecondChallenge →
      SecondResponse)
    (translate : Query → FirstChallenge → SecondChallenge → Tape →
      Tape)
    (hfirst : ∀ query firstChallenge secondChallenge tape,
      firstTo (translate query firstChallenge secondChallenge tape)
          firstChallenge = firstFrom tape firstChallenge)
    (hsecond : ∀ query firstChallenge secondChallenge tape,
      secondTo (translate query firstChallenge secondChallenge tape)
          firstChallenge secondChallenge =
        secondFrom tape firstChallenge secondChallenge)
    (hinjective : ∀ query firstChallenge secondChallenge,
      Function.Injective (translate query firstChallenge secondChallenge)) :
    Function.Injective
      (sequentialTapeTranslate verifier firstFrom secondFrom translate) := by
  rintro ⟨left, coinsLeft⟩ ⟨right, coinsRight⟩ hequal
  have hcoins : coinsLeft = coinsRight := congrArg Prod.snd hequal
  subst coinsRight
  have htapes := congrArg Prod.fst hequal
  let firstChallenge := verifier.firstChallenge coinsLeft
  let firstLeft := firstFrom left firstChallenge
  let firstRight := firstFrom right firstChallenge
  let secondChallengeLeft := verifier.secondChallenge coinsLeft firstLeft
  let secondChallengeRight := verifier.secondChallenge coinsLeft firstRight
  let secondLeft := secondFrom left firstChallenge secondChallengeLeft
  let secondRight := secondFrom right firstChallenge secondChallengeRight
  let queryLeft := verifier.query coinsLeft firstLeft secondLeft
  let queryRight := verifier.query coinsLeft firstRight secondRight
  have htranslated :
      translate queryLeft firstChallenge secondChallengeLeft left =
        translate queryRight firstChallenge secondChallengeRight right := by
    simpa only [sequentialTapeTranslate, firstChallenge, firstLeft, firstRight,
      secondChallengeLeft, secondChallengeRight, secondLeft, secondRight,
      queryLeft, queryRight] using htapes
  have hfirstResponses : firstLeft = firstRight := by
    dsimp only [firstLeft, firstRight]
    rw [← hfirst queryLeft firstChallenge secondChallengeLeft left,
      ← hfirst queryRight firstChallenge secondChallengeRight right]
    exact congrArg (fun tape => firstTo tape firstChallenge) htranslated
  have hsecondChallenges : secondChallengeLeft = secondChallengeRight := by
    simp only [secondChallengeLeft, secondChallengeRight, hfirstResponses]
  have hsecondResponses : secondLeft = secondRight := by
    dsimp only [secondLeft, secondRight]
    rw [← hsecond queryLeft firstChallenge secondChallengeLeft left,
      ← hsecond queryRight firstChallenge secondChallengeRight right]
    rw [hsecondChallenges] at htranslated ⊢
    exact congrArg
      (fun tape => secondTo tape firstChallenge secondChallengeRight) htranslated
  have hqueries : queryLeft = queryRight := by
    simp only [queryLeft, queryRight, hfirstResponses, hsecondResponses]
  have hfixed :
      translate queryLeft firstChallenge secondChallengeLeft left =
        translate queryLeft firstChallenge secondChallengeLeft right := by
    simpa only [hqueries, hsecondChallenges] using htranslated
  exact Prod.ext
    (hinjective queryLeft firstChallenge secondChallengeLeft hfixed) rfl

noncomputable def sequentialTapeTranslateEquiv
    [Fintype Tape] [Fintype Coins]
    (verifier : SequentialResponseAdaptiveVerifier Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query)
    (firstFrom firstTo : Tape → FirstChallenge → FirstResponse)
    (secondFrom secondTo : Tape → FirstChallenge → SecondChallenge →
      SecondResponse)
    (translate : Query → FirstChallenge → SecondChallenge → Tape →
      Tape)
    (hfirst : ∀ query firstChallenge secondChallenge tape,
      firstTo (translate query firstChallenge secondChallenge tape)
          firstChallenge = firstFrom tape firstChallenge)
    (hsecond : ∀ query firstChallenge secondChallenge tape,
      secondTo (translate query firstChallenge secondChallenge tape)
          firstChallenge secondChallenge =
        secondFrom tape firstChallenge secondChallenge)
    (hinjective : ∀ query firstChallenge secondChallenge,
      Function.Injective (translate query firstChallenge secondChallenge)) :
    (Tape × Coins) ≃ (Tape × Coins) :=
  Equiv.ofBijective
    (sequentialTapeTranslate verifier firstFrom secondFrom translate)
    (sequentialTapeTranslate_injective verifier firstFrom firstTo secondFrom
      secondTo translate hfirst hsecond hinjective).bijective_of_finite

theorem sameDistribution_of_sequentialTapeTranslate
    [Fintype Tape] [Fintype Coins] [DecidableEq View]
    (verifier : SequentialResponseAdaptiveVerifier Coins FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query)
    (firstFrom firstTo : Tape → FirstChallenge → FirstResponse)
    (secondFrom secondTo : Tape → FirstChallenge → SecondChallenge →
      SecondResponse)
    (translate : Query → FirstChallenge → SecondChallenge → Tape →
      Tape)
    (hfirst : ∀ query firstChallenge secondChallenge tape,
      firstTo (translate query firstChallenge secondChallenge tape)
          firstChallenge = firstFrom tape firstChallenge)
    (hsecond : ∀ query firstChallenge secondChallenge tape,
      secondTo (translate query firstChallenge secondChallenge tape)
          firstChallenge secondChallenge =
        secondFrom tape firstChallenge secondChallenge)
    (hinjective : ∀ query firstChallenge secondChallenge,
      Function.Injective (translate query firstChallenge secondChallenge))
    (fromView toView : Tape × Coins → View)
    (hview : ∀ randomness, fromView randomness = toView
      (sequentialTapeTranslate verifier firstFrom secondFrom translate randomness)) :
    SameDistribution fromView toView := by
  apply sameDistribution_of_equiv
    (sequentialTapeTranslateEquiv verifier firstFrom firstTo secondFrom secondTo
      translate hfirst hsecond hinjective)
  exact hview

end TapeTranslation

end LigeroFamily.ZeroKnowledge
