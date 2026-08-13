import Ligero.Common.Protocol.Policy
import Ligero.Common.Soundness.SchemeLiftBridge

/-!
# Policy-generic lift-list certificates

The transcript's arithmetic portion is opaque.  All extraction uses the
policy's proximity weights and selected proximity response.
-/

namespace Ligero.Common

open CodingTheory MultiplicativeCode

variable {F Equations CheckedMask DirectMask Challenge Response : Type*}
variable [Field F] [Fintype F] [DecidableEq F]
variable [Fintype Equations] [DecidableEq Equations]
variable [Fintype CheckedMask] [DecidableEq CheckedMask]
variable [Fintype Challenge] [DecidableEq Challenge]
variable {q r w n nw nq e g radius L d : ℕ}

variable {C : MultiplicativeCode F r w n}
variable {layout : ConstraintLayout F q w}
variable {policy : SchemeProtocolPolicy (Equations := Equations) C layout
  Challenge Response CheckedMask DirectMask nw nq 1}
variable {oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1}
variable {respond : Challenge → Response}

/-- A fixed Johnson list shared by every arithmetic policy with the same
proximity-tested rows. -/
structure PolicyLiftListCertificate
    (policy : SchemeProtocolPolicy (Equations := Equations) C layout
      Challenge Response CheckedMask DirectMask nw nq 1)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (respond : Challenge → Response)
    (e g radius L : ℕ) where
  candidates : Finset (SchemeLiftCandidate C oracle radius)
  failure : Finset Challenge
  list_card : candidates.card ≤ L
  lift : ∀ challenge, challenge ∉ failure →
    policy.proximityResponse (respond challenge) 0 ∈ C.base →
    (schemeProximityDisagreement oracle (policy.proximityWeights challenge 0)
      (policy.proximityResponse (respond challenge) 0)).card ≤ e →
    ∃ candidate ∈ candidates,
      candidate.proximityRow (policy.proximityWeights challenge 0) =
          policy.proximityResponse (respond challenge) 0 ∧
        (candidate.remainingBadColumns (policy.proximityWeights challenge 0)
          (policy.proximityResponse (respond challenge) 0)).card ≤ g

omit [Fintype F] [Fintype Equations] [DecidableEq Equations]
    [DecidableEq CheckedMask] [Fintype Challenge] [DecidableEq Challenge] in
theorem policyProximity_query_subset_agreement
    (statement : ConstraintSystem F nw nq q Equations)
    (challenge : Challenge) (response : Response) (query : QuerySet n r)
    (haccept : policy.accepts statement challenge response query
      (openSchemeOracle oracle query)) :
    query.coordinates ⊆ schemeProximityAgreement oracle
      (policy.proximityWeights challenge 0)
      (policy.proximityResponse response 0) := by
  exact schemeProximity_query_subset_agreement oracle
    (policy.proximityWeights challenge 0)
    (policy.proximityResponse response 0) query
    (policy.accepts_proximity statement challenge response query
      (openSchemeOracle oracle query) haccept 0)

omit [Fintype F] [Fintype Equations] [DecidableEq Equations]
    [DecidableEq CheckedMask] [Fintype Challenge] [DecidableEq Challenge] in
theorem policyProximity_far_cover
    (statement : ConstraintSystem F nw nq q Equations)
    (challenge : Challenge) (response : Response) (query : QuerySet n r)
    (haccept : policy.accepts statement challenge response query
      (openSchemeOracle oracle query))
    (hfar : e < (schemeProximityDisagreement oracle
      (policy.proximityWeights challenge 0)
      (policy.proximityResponse response 0)).card) :
    query.coordinates ⊆ schemeProximityAgreement oracle
        (policy.proximityWeights challenge 0)
        (policy.proximityResponse response 0) ∧
      (schemeProximityAgreement oracle (policy.proximityWeights challenge 0)
        (policy.proximityResponse response 0)).card ≤ n - e - 1 := by
  exact schemeProximity_far_cover oracle
    (policy.proximityWeights challenge 0)
    (policy.proximityResponse response 0) query
    (policy.accepts_proximity statement challenge response query
      (openSchemeOracle oracle query) haccept 0) hfar

namespace PolicyLiftListCertificate

omit [Fintype Equations] [DecidableEq Equations] [DecidableEq CheckedMask]
    [Fintype Challenge] [DecidableEq Challenge] in
/-- Construct the fixed list from policy-independent punctured lift
witnesses. -/
theorem exists_of_gLiftWitnesses
    (hmin : HasMinimumDistanceAtLeast C.baseCode d)
    (hradius : e + g < d)
    (hden : 0 < CodingTheory.InterleavedJohnson.denominator n d (e + g))
    (failure : Finset Challenge)
    (hwitness : ∀ challenge, challenge ∉ failure →
      policy.proximityResponse (respond challenge) 0 ∈ C.base →
      (schemeProximityDisagreement oracle (policy.proximityWeights challenge 0)
        (policy.proximityResponse (respond challenge) 0)).card ≤ e →
      Nonempty (SchemeGLiftWitness C oracle
        (policy.proximityWeights challenge 0)
        (policy.proximityResponse (respond challenge) 0) g)) :
    ∃ certificate : PolicyLiftListCertificate policy oracle respond e g (e + g)
      (CodingTheory.InterleavedJohnson.listBound n d (e + g)),
      certificate.failure = failure := by
  let candidates :=
    (Finset.univ : Finset (SchemeLiftCandidate C oracle (e + g)))
  have hradiusLength : e + g ≤ n :=
    (Nat.le_of_lt hradius).trans hmin.distance_le_length
  have hlistCard : candidates.card ≤
      CodingTheory.InterleavedJohnson.listBound n d (e + g) :=
    SchemeLiftCandidate.univ_card_le_listBound C oracle hmin
      hradiusLength hradius hden
  refine ⟨{
    candidates := candidates
    failure := failure
    list_card := hlistCard
    lift := ?_ }, rfl⟩
  intro challenge hnotFailure hresponse hsmall
  obtain ⟨witness⟩ := hwitness challenge hnotFailure hresponse hsmall
  obtain ⟨candidate, haggregate, hremaining⟩ :=
    witness.exists_schemeLiftCandidate hresponse hsmall hmin hradius
  exact ⟨candidate, Finset.mem_univ candidate, haggregate, hremaining⟩

end PolicyLiftListCertificate

end Ligero.Common
