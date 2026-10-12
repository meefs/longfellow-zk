import LigeroFamily.Protocol.MaskScheme
import LigeroFamily.Soundness.CodewordInjective

/-!
# Canonical valid Ligero responses

The response-rigid Fiat--Shamir compiler hashes the response message itself.
It therefore needs the protocol's evaluation-row presentation to be
canonical on messages that can actually be accepted.  This file proves that
adapter:

* acceptance implies query-independent code membership for all three response
  families; and
* when `2k ≤ n`, their committed codewords determine the whole response.

Invalid evaluation rows may still be serialized and queried to the random
oracle, but they cannot be attributed to an accepting transcript.
-/

set_option autoImplicit false
set_option relaxedAutoImplicit false

namespace LigeroFamily

open MultiplicativeCode

variable {F Equations CheckedMask DirectMask : Type*}
variable [Field F] [Fintype Equations] [Fintype CheckedMask]
variable {r w n nw nq repetitions : ℕ}

/-- The query-independent validity predicate for a scheme response. -/
def Response.Valid (C : MultiplicativeCode F r w n)
    (response : Response F r w n repetitions) : Prop :=
  ∀ h : Fin repetitions,
    response.proximity h ∈ C.base ∧
      response.linear h ∈ C.response ∧
      response.quadratic h ∈ C.response

/-- The tuple of committed codewords canonically represented by a response. -/
structure Response.Codewords (F : Type*) (n repetitions : ℕ) where
  proximity : Fin repetitions → CodingTheory.Word F n
  linear : Fin repetitions → CodingTheory.Word F n
  quadratic : Fin repetitions → CodingTheory.Word F n

omit [Field F] in
@[ext] theorem Response.Codewords.ext
    {first second : Response.Codewords F n repetitions}
    (hproximity : first.proximity = second.proximity)
    (hlinear : first.linear = second.linear)
    (hquadratic : first.quadratic = second.quadratic) : first = second := by
  cases first
  cases second
  simp_all

/-- Project an evaluation-form response to its three committed codeword
families. -/
def Response.codewords (response : Response F r w n repetitions) :
    Response.Codewords F n repetitions where
  proximity h := codeword (response.proximity h)
  linear h := codeword (response.linear h)
  quadratic h := codeword (response.quadratic h)

/-- All membership checks used by `Response.Valid` occur before the local
query-coordinate checks in the verifier definition. -/
theorem SchemeVerifier.valid_of_accepts
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (challenge : SchemeChallenge F CheckedMask nw nq repetitions Equations)
    (response : Response F r w n repetitions) (query : QuerySet n r)
    (opening : SchemeOpening F CheckedMask DirectMask nw nq repetitions n r query)
    (haccept : SchemeVerifier.Accepts C scheme statement challenge response query opening) :
    response.Valid C := by
  intro h
  exact ⟨(haccept h).1.1, (haccept h).2.1.1, (haccept h).2.2.1⟩

/-- **Valid-response rigidity.**  On valid response messages, the committed
codeword tuple is injective.  This is D1's semantic form for the current
evaluation-row protocol representation. -/
theorem Response.eq_of_valid_codewords_eq
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    {first second : Response F r w n repetitions}
    (hfirst : first.Valid C) (hsecond : second.Valid C)
    (hcodewords : first.codewords = second.codewords) :
    first = second := by
  apply Response.ext
  · funext h
    apply C.baseRow_eq_of_codeword_eq (hfirst h).1 (hsecond h).1
    exact congrFun (congrArg Response.Codewords.proximity hcodewords) h
  · funext h
    apply C.responseRow_eq_of_codeword_eq h2k (hfirst h).2.1 (hsecond h).2.1
    exact congrFun (congrArg Response.Codewords.linear hcodewords) h
  · funext h
    apply C.responseRow_eq_of_codeword_eq h2k (hfirst h).2.2 (hsecond h).2.2
    exact congrFun (congrArg Response.Codewords.quadratic hcodewords) h




end LigeroFamily
