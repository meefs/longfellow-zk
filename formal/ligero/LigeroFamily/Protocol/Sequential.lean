import LigeroFamily.Protocol.IPCP

/-!
# Two-stage public-coin IPCP semantics

The first response is fixed before the second public challenge.  This is the
protocol-order property needed by sequential protocols: a malicious prover cannot choose
the quotient-remainder coset after seeing the proximity weights.
-/

namespace LigeroFamily

/-- A public-coin IPCP with one oracle, two sequential challenge-response
stages, and a final bounded oracle opening. -/
structure SequentialPublicCoinIPCP
    (Statement Oracle FirstChallenge FirstResponse SecondChallenge
      SecondResponse Query : Type*)
    (Opening : Query → Type*) where
  language : Statement → Prop
  openOracle : (oracle : Oracle) → (query : Query) → Opening query
  verify : Statement → FirstChallenge → FirstResponse → SecondChallenge →
    SecondResponse → (query : Query) → Opening query → Bool

/-- A malicious sequential prover.  `firstRespond` cannot see the second
challenge, while `secondRespond` sees the already fixed first response. -/
structure SequentialIPCPProver
    (Statement Oracle FirstChallenge FirstResponse SecondChallenge
      SecondResponse : Type*) where
  commit : Statement → Oracle
  firstRespond : Statement → Oracle → FirstChallenge → FirstResponse
  secondRespond : Statement → Oracle → FirstChallenge → FirstResponse →
    SecondChallenge → SecondResponse

structure SequentialTranscript
    (Oracle FirstChallenge FirstResponse SecondChallenge SecondResponse
      Query : Type*) (Opening : Query → Type*) where
  oracle : Oracle
  firstChallenge : FirstChallenge
  firstResponse : FirstResponse
  secondChallenge : SecondChallenge
  secondResponse : SecondResponse
  query : Query
  opening : Opening query

namespace SequentialPublicCoinIPCP

variable {Statement Oracle FirstChallenge FirstResponse SecondChallenge
  SecondResponse Query : Type*}
variable {Opening : Query → Type*}

def run
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (prover : SequentialIPCPProver Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse)
    (statement : Statement)
    (coins : FirstChallenge × SecondChallenge × Query) :
    SequentialTranscript Oracle FirstChallenge FirstResponse SecondChallenge
      SecondResponse Query Opening :=
  let oracle := prover.commit statement
  let firstResponse := prover.firstRespond statement oracle coins.1
  let secondResponse := prover.secondRespond statement oracle coins.1
    firstResponse coins.2.1
  { oracle
    firstChallenge := coins.1
    firstResponse
    secondChallenge := coins.2.1
    secondResponse
    query := coins.2.2
    opening := protocol.openOracle oracle coins.2.2 }

/-- Changing the second challenge or final query cannot change the first
response.  This elementary fact is the binding condition used by the
sequential soundness reduction. -/
theorem run_firstResponse_eq
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (prover : SequentialIPCPProver Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse)
    (statement : Statement)
    (firstChallenge : FirstChallenge)
    (firstCoins secondCoins : SecondChallenge × Query) :
    (protocol.run prover statement (firstChallenge, firstCoins)).firstResponse =
      (protocol.run prover statement (firstChallenge, secondCoins)).firstResponse :=
  rfl

def accepts
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (prover : SequentialIPCPProver Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse)
    (statement : Statement)
    (coins : FirstChallenge × SecondChallenge × Query) : Bool :=
  let transcript := protocol.run prover statement coins
  protocol.verify statement transcript.firstChallenge transcript.firstResponse
    transcript.secondChallenge transcript.secondResponse transcript.query
    transcript.opening

def acceptanceRate
    [Fintype FirstChallenge] [DecidableEq FirstChallenge]
    [Fintype SecondChallenge] [DecidableEq SecondChallenge]
    [Fintype Query] [DecidableEq Query]
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (prover : SequentialIPCPProver Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse)
    (statement : Statement) : ℚ :=
  LigeroFamily.finiteProtocolAcceptanceRate
    (protocol.accepts prover statement)

def SoundnessAtMost
    [Fintype FirstChallenge] [DecidableEq FirstChallenge]
    [Fintype SecondChallenge] [DecidableEq SecondChallenge]
    [Fintype Query] [DecidableEq Query]
    [Nonempty FirstChallenge] [Nonempty SecondChallenge] [Nonempty Query]
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    (error : ℚ) : Prop :=
  ∀ statement, ¬protocol.language statement →
    ∀ prover, protocol.acceptanceRate prover statement ≤ error

def PerfectCompleteness
    (protocol : SequentialPublicCoinIPCP Statement Oracle FirstChallenge
      FirstResponse SecondChallenge SecondResponse Query Opening)
    {Witness : Type*} (relation : Statement → Witness → Prop)
    (honestProver : Witness → SequentialIPCPProver Statement Oracle
      FirstChallenge FirstResponse SecondChallenge SecondResponse) : Prop :=
  ∀ statement witness, relation statement witness →
    ∀ coins, protocol.accepts (honestProver witness) statement coins = true

end SequentialPublicCoinIPCP

end LigeroFamily
