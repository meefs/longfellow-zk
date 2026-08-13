import Ligero.Common.Soundness.PolicySelectedMCA



namespace Ligero.Common

open MultiplicativeCode

variable {F Equations CheckedMask DirectMask : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable [Fintype CheckedMask] [DecidableEq CheckedMask]
variable {r w n nw nq : ℕ}

abbrev SchemeArithmeticTail (F Equations : Type*) (nq : ℕ) :=
  (Equations → F) × (Fin nq → F)

def schemeChallengeProductEquiv :
    SchemeChallenge F CheckedMask nw nq 1 Equations ≃
      SchemeArithmeticTail F Equations nq ×
        SchemeSelectedMCA.Weights F CheckedMask nw nq :=
  (Equiv.funUnique (Fin 1)
    (SchemeRoundChallenge F CheckedMask nw nq 1 Equations)).trans
    ((schemeRoundChallengeEquiv F CheckedMask Equations nw nq 1).trans
      (Equiv.prodComm _ _))




noncomputable def schemeExtractorPolicy
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n) :
    SchemeExtractorPolicy
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) C scheme)
      (SchemeArithmeticTail F Equations nq) where
  challengeProductEquiv := schemeChallengeProductEquiv
  weights_eq := by intro challenge; rfl

end Ligero.Common
