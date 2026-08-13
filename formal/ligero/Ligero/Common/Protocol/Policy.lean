import Ligero.Common.Protocol.Layout
import Ligero.Common.Protocol.IPCP










namespace Ligero.Common

open MultiplicativeCode

variable {F Equations CheckedMask DirectMask Challenge Response : Type*}
variable [Field F] [Fintype Equations]
variable [Fintype CheckedMask]
variable {q r w n nw nq repetitions : ℕ}

/-- Everything the common extractor stack observes about a concrete Ligero
protocol.  In particular, it never inspects the arithmetic transcript. -/
structure SchemeProtocolPolicy
    (C : MultiplicativeCode F r w n)
    (layout : ConstraintLayout F q w)
    (Challenge Response : Type*)
    (CheckedMask DirectMask : Type*)
    (nw nq repetitions : ℕ) [Fintype CheckedMask] where
  proximityWeights : Challenge → Fin repetitions →
    SchemeTestedRow CheckedMask nw nq repetitions → F
  proximityResponse : Response → Fin repetitions → EvaluationRow F r w n
  accepts : ConstraintSystem F nw nq q Equations → Challenge → Response →
    (query : QuerySet n r) →
      SchemeOpening F CheckedMask DirectMask nw nq repetitions n r query → Prop
  accepts_proximity : ∀ statement challenge response query opening,
    accepts statement challenge response query opening →
    ∀ h, SchemeVerifier.ProximityAccepts C (proximityWeights challenge h)
      (proximityResponse response h) query opening h

namespace SchemeProtocolPolicy

variable {C : MultiplicativeCode F r w n}
variable {layout : ConstraintLayout F q w}
variable (policy : SchemeProtocolPolicy C layout Challenge Response
  CheckedMask DirectMask nw nq repetitions)

/-- Every policy induces the same finite public-coin IPCP shape. -/
noncomputable def protocol :
    PublicCoinIPCP
      (ConstraintSystem F nw nq q Equations)
      (SchemeOracle F CheckedMask DirectMask nw nq n repetitions)
      Challenge Response (QuerySet n r)
      (SchemeOpening F CheckedMask DirectMask nw nq repetitions n r) where
  language := ConstraintSystem.Language
  openOracle := openSchemeOracle
  verify statement challenge response query opening := by
    classical
    exact decide (policy.accepts statement challenge response query opening)

end SchemeProtocolPolicy

namespace SchemeVerifier

variable {C : MultiplicativeCode F r w n}



noncomputable def policy
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n) :
    SchemeProtocolPolicy (Equations := Equations) C
      (ConstraintLayout.identity w)
      (SchemeChallenge F CheckedMask nw nq repetitions Equations)
      (Ligero.Common.Response F r w n repetitions)
      CheckedMask DirectMask nw nq repetitions where
  proximityWeights challenge h := (challenge h).proximity
  proximityResponse response h := response.proximity h
  accepts := Accepts C scheme
  accepts_proximity := by
    intro statement challenge response query opening haccept h
    exact (haccept h).1

end SchemeVerifier

end Ligero.Common
