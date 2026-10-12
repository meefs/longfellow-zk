import LigeroFamily.Soundness.CanonicalResponse
import LigeroFamily.Soundness.ProfiledLiftList
import LigeroFamily.Soundness.PolicyProfiledMaster
import CodingTheory.ListDecoding.InterleavedJohnson

/-!
# Finite response lists for Case A of response-rigid Fiat--Shamir

Case A fixes the commitment and batching challenge before the response is
chosen.  A response whose accepting-coordinate set is larger than the
canonical floor must be charged to a finite list.  This file proves the
coding-theoretic part of that statement: one Johnson list for each committed
codeword family, followed by valid-response canonicity.
-/

set_option autoImplicit false
set_option relaxedAutoImplicit false
set_option linter.unusedSectionVars false

namespace LigeroFamily.RigidResponseList

open CodingTheory

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]
variable {n d agreement : ℕ}

private def responseFintypeEquiv {r w repetitions : ℕ} :
    ((Fin repetitions → EvaluationRow F r w n) ×
      (Fin repetitions → EvaluationRow F r w n) ×
      (Fin repetitions → EvaluationRow F r w n)) ≃
        Response F r w n repetitions where
  toFun value := ⟨value.1, value.2.1, value.2.2⟩
  invFun response := (response.proximity, response.linear, response.quadratic)
  left_inv _ := rfl
  right_inv _ := rfl

noncomputable instance responseFintype {r w repetitions : ℕ} :
    Fintype (Response F r w n repetitions) :=
  letI : Fintype (Fin repetitions → EvaluationRow F r w n) := inferInstance
  Fintype.ofEquiv _ responseFintypeEquiv

/-- Coordinates on which a codeword agrees with a fixed received word. -/
def agreementCoordinates (received word : Word F n) : Finset (Fin n) :=
  Finset.univ.filter fun coordinate ↦ received coordinate = word coordinate

/-- The complete list of codewords agreeing with `received` in at least
`agreement` coordinates. -/
noncomputable def codewordList (C : LinearCode F n) (received : Word F n)
    (agreement : ℕ) : Finset (Word F n) := by
  classical
  exact Finset.univ.filter fun word ↦
    word ∈ C ∧ agreement ≤ (agreementCoordinates received word).card

private def singletonMatrix (word : Word F n) : Unit → Word F n :=
  fun _ ↦ word

private theorem singletonMatrix_injective :
    Function.Injective (singletonMatrix (F := F) (n := n)) := by
  intro first second heq
  exact congrFun heq ()

private theorem matrixErrors_singletonMatrix
    (received word : Word F n) :
    matrixErrorCoordinates (singletonMatrix received) (singletonMatrix word) =
      Finset.univ \ agreementCoordinates received word := by
  classical
  ext coordinate
  simp [matrixErrorCoordinates, singletonMatrix, agreementCoordinates]

/-- A one-row specialization of the proved interleaved Johnson theorem. -/
theorem codewordList_card_le
    (C : LinearCode F n) (received : Word F n)
    (hmin : HasMinimumDistanceAtLeast C d)
    (hradius : n - agreement < d)
    (hden : 0 < InterleavedJohnson.denominator n d (n - agreement)) :
    (codewordList C received agreement).card ≤
      InterleavedJohnson.listBound n d (n - agreement) := by
  classical
  let words := codewordList C received agreement
  let matrices : Finset (Unit → Word F n) :=
    words.image singletonMatrix
  have hmatricesCard : matrices.card = words.card := by
    dsimp [matrices]
    rw [Finset.card_image_of_injective _ singletonMatrix_injective]
  have hcode (candidate : Unit → Word F n) (hcandidate : candidate ∈ matrices)
      (row : Unit) : candidate row ∈ C := by
    obtain ⟨word, hword, rfl⟩ := Finset.mem_image.mp hcandidate
    have hlisted := (Finset.mem_filter.mp hword).2
    exact hlisted.1
  have hclose (candidate : Unit → Word F n) (hcandidate : candidate ∈ matrices) :
      (matrixErrorCoordinates (singletonMatrix received) candidate).card ≤
        n - agreement := by
    obtain ⟨word, hword, rfl⟩ := Finset.mem_image.mp hcandidate
    have hlisted := (Finset.mem_filter.mp hword).2
    rw [matrixErrors_singletonMatrix]
    rw [Finset.card_sdiff]
    simpa using Nat.sub_le_sub_left hlisted.2 n
  have hbound := InterleavedJohnson.card_le_listBound C
    (singletonMatrix received) matrices hmin hcode hclose
    (Nat.sub_le n agreement) hradius hden
  rwa [hmatricesCard] at hbound

/-! ## Product-list counting -/

variable {Rsp A B CWord : Type*}

/-- An injective three-component representation bounds a response family by
the product of its three component lists. -/
theorem card_le_three_lists
    (responses : Finset Rsp) (first : Finset A) (second : Finset B)
    (third : Finset CWord) (encode : Rsp → A × B × CWord)
    (hmaps : ∀ response ∈ responses,
      (encode response).1 ∈ first ∧
      (encode response).2.1 ∈ second ∧
      (encode response).2.2 ∈ third)
    (hinjective : Set.InjOn encode responses) :
    responses.card ≤ first.card * second.card * third.card := by
  let target := (first ×ˢ second) ×ˢ third
  calc
    responses.card ≤ target.card := by
      apply Finset.card_le_card_of_injOn
        (fun response ↦ (((encode response).1, (encode response).2.1),
          (encode response).2.2))
      · intro response hresponse
        have h := hmaps response hresponse
        exact Finset.mem_product.mpr
          ⟨Finset.mem_product.mpr ⟨h.1, h.2.1⟩, h.2.2⟩
      · intro left hleft right hright heq
        apply hinjective hleft hright
        apply Prod.ext
        · exact congrArg (fun value : (A × B) × CWord ↦ value.1.1) heq
        · apply Prod.ext
          · exact congrArg (fun value : (A × B) × CWord ↦ value.1.2) heq
          · exact congrArg (fun value : (A × B) × CWord ↦ value.2) heq
    _ = first.card * second.card * third.card := by simp [target]


theorem card_le_two_lists
    (responses : Finset Rsp) (first : Finset A) (second : Finset B)
    (encode : Rsp → A × B)
    (hmaps : ∀ response ∈ responses,
      (encode response).1 ∈ first ∧ (encode response).2 ∈ second)
    (hinjective : Set.InjOn encode responses) :
    responses.card ≤ first.card * second.card := by
  calc
    responses.card ≤ (first ×ˢ second).card := by
      exact Finset.card_le_card_of_injOn encode
        (fun response hresponse ↦ Finset.mem_product.mpr (hmaps response hresponse))
        hinjective
    _ = first.card * second.card := by simp

/-! ## Ligero response specializations (one repetition) -/

open LigeroFamily
open LigeroFamily.MultiplicativeCode

variable {r w : ℕ}

def schemeTuple (response : Response F r w n 1) :
    Word F n × Word F n × Word F n :=
  (response.codewords.proximity 0,
    response.codewords.linear 0, response.codewords.quadratic 0)

def schemeMatrix (response : Response F r w n 1) : Fin 3 → Word F n := fun row ↦
  if row = 0 then response.codewords.proximity 0
  else if row = 1 then response.codewords.linear 0
  else response.codewords.quadratic 0


def schemeReceivedMatrix
    (receivedProximity receivedLinear receivedQuadratic : Word F n) :
    Fin 3 → Word F n := fun row ↦
  if row = 0 then receivedProximity
  else if row = 1 then receivedLinear
  else receivedQuadratic

def directReceivedMatrix
    (receivedProximity receivedLinear : Word F n) : Fin 2 → Word F n := fun row ↦
  if row = 0 then receivedProximity
  else receivedLinear

def schemeJointAgreement
    (receivedProximity receivedLinear receivedQuadratic : Word F n)
    (response : Response F r w n 1) : Finset (Fin n) :=
  agreementCoordinates receivedProximity (response.codewords.proximity 0) ∩
    agreementCoordinates receivedLinear (response.codewords.linear 0) ∩
    agreementCoordinates receivedQuadratic (response.codewords.quadratic 0)

theorem matrixErrorCoordinates_schemeMatrix
    (receivedProximity receivedLinear receivedQuadratic : Word F n)
    (response : Response F r w n 1) :
    matrixErrorCoordinates
        (schemeReceivedMatrix receivedProximity receivedLinear receivedQuadratic)
        (schemeMatrix response) =
      Finset.univ \ schemeJointAgreement receivedProximity receivedLinear
        receivedQuadratic response := by
  classical
  ext coordinate
  simp only [matrixErrorCoordinates, Finset.mem_filter, Finset.mem_univ,
    true_and, Finset.mem_sdiff]
  constructor
  · rintro ⟨row, hrow⟩
    refine ?_
    intro hagree
    simp only [schemeJointAgreement, Finset.mem_inter, agreementCoordinates,
      Finset.mem_filter, Finset.mem_univ, true_and] at hagree
    fin_cases row
    · exact hrow (by simpa [schemeReceivedMatrix, schemeMatrix] using hagree.1.1)
    · exact hrow (by simpa [schemeReceivedMatrix, schemeMatrix] using hagree.1.2)
    · exact hrow (by simpa [schemeReceivedMatrix, schemeMatrix] using hagree.2)
  · intro hagree
    simp only [schemeJointAgreement, Finset.mem_inter, agreementCoordinates,
      Finset.mem_filter, Finset.mem_univ, true_and, not_and_or] at hagree
    rcases hagree with (hagree | hagree) | hagree
    · exact ⟨0, by simpa [schemeReceivedMatrix, schemeMatrix] using hagree⟩
    · exact ⟨1, by simpa [schemeReceivedMatrix, schemeMatrix] using hagree⟩
    · exact ⟨2, by simpa [schemeReceivedMatrix, schemeMatrix] using hagree⟩

/-- The protocol-facing base code embeds in the response code. -/
theorem baseCode_le_responseCode (C : MultiplicativeCode F r w n) :
    C.baseCode ≤ C.responseCode := by
  intro word hword
  obtain ⟨row, hrow, rfl⟩ := C.exists_base_row_of_mem_baseCode hword
  exact C.codeword_mem_responseCode (C.base_le_response hrow)

theorem schemeTuple_injOn_valid
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (responses : Finset (Response F r w n 1))
    (hvalid : ∀ response ∈ responses, response.Valid C) :
    Set.InjOn (schemeTuple (F := F) (r := r) (w := w) (n := n))
      (↑responses : Set (Response F r w n 1)) := by
  intro first hfirst second hsecond heq
  apply Response.eq_of_valid_codewords_eq C h2k
    (hvalid first hfirst) (hvalid second hsecond)
  apply Response.Codewords.ext
  · funext repetition
    have hrepetition : repetition = (0 : Fin 1) := Subsingleton.elim _ _
    subst repetition
    exact congrArg (fun value ↦ value.1) heq
  · funext repetition
    have hrepetition : repetition = (0 : Fin 1) := Subsingleton.elim _ _
    subst repetition
    exact congrArg (fun value ↦ value.2.1) heq
  · funext repetition
    have hrepetition : repetition = (0 : Fin 1) := Subsingleton.elim _ _
    subst repetition
    exact congrArg (fun value ↦ value.2.2) heq

theorem schemeMatrix_injOn_valid
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (responses : Finset (Response F r w n 1))
    (hvalid : ∀ response ∈ responses, response.Valid C) :
    Set.InjOn (schemeMatrix (F := F) (r := r) (w := w) (n := n))
      (↑responses : Set (Response F r w n 1)) := by
  intro first hfirst second hsecond heq
  apply schemeTuple_injOn_valid C h2k responses hvalid hfirst hsecond
  apply Prod.ext
  · simpa [schemeMatrix, schemeTuple] using congrFun heq (0 : Fin 3)
  · apply Prod.ext
    · simpa [schemeMatrix, schemeTuple] using congrFun heq (1 : Fin 3)
    · simpa [schemeMatrix, schemeTuple] using congrFun heq (2 : Fin 3)

theorem schemeResponses_card_le
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (responses : Finset (Response F r w n 1))
    (receivedProximity receivedLinear receivedQuadratic : Word F n)
    (hvalid : ∀ response ∈ responses, response.Valid C)
    (hagrees : ∀ response ∈ responses,
      agreement ≤ (agreementCoordinates receivedProximity
        (response.codewords.proximity 0)).card ∧
      agreement ≤ (agreementCoordinates receivedLinear
        (response.codewords.linear 0)).card ∧
      agreement ≤ (agreementCoordinates receivedQuadratic
        (response.codewords.quadratic 0)).card)
    (hbase : HasMinimumDistanceAtLeast C.baseCode d)
    {responseDistance : ℕ}
    (hresponse : HasMinimumDistanceAtLeast C.responseCode responseDistance)
    (hbaseRadius : n - agreement < d)
    (hresponseRadius : n - agreement < responseDistance)
    (hbaseDen : 0 < InterleavedJohnson.denominator n d (n - agreement))
    (hresponseDen : 0 <
      InterleavedJohnson.denominator n responseDistance (n - agreement)) :
    responses.card ≤
      InterleavedJohnson.listBound n d (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement) := by
  classical
  let proximity := codewordList C.baseCode receivedProximity agreement
  let linear := codewordList C.responseCode receivedLinear agreement
  let quadratic := codewordList C.responseCode receivedQuadratic agreement
  have htuple : responses.card ≤ proximity.card * linear.card * quadratic.card :=
    card_le_three_lists responses proximity linear quadratic schemeTuple
      (fun response hresponseMem ↦ by
        have hv := hvalid response hresponseMem
        have ha := hagrees response hresponseMem
        exact ⟨Finset.mem_filter.mpr
            ⟨Finset.mem_univ _, C.codeword_mem_baseCode (hv 0).1, ha.1⟩,
          Finset.mem_filter.mpr
            ⟨Finset.mem_univ _, C.codeword_mem_responseCode (hv 0).2.1, ha.2.1⟩,
          Finset.mem_filter.mpr
            ⟨Finset.mem_univ _, C.codeword_mem_responseCode (hv 0).2.2, ha.2.2⟩⟩)
      (schemeTuple_injOn_valid C h2k responses hvalid)
  exact htuple.trans (Nat.mul_le_mul
    (Nat.mul_le_mul
      (codewordList_card_le C.baseCode receivedProximity hbase
        hbaseRadius hbaseDen)
      (codewordList_card_le C.responseCode receivedLinear hresponse
        hresponseRadius hresponseDen))
    (codewordList_card_le C.responseCode receivedQuadratic hresponse
      hresponseRadius hresponseDen))


/-- Listing the three response components separately loses their common
agreement set and multiplies three Johnson bounds.  All components lie in the
single response code, so the interleaved Johnson theorem gives one list bound
for the complete response matrix. -/
theorem schemeResponses_card_le_interleaved
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (responses : Finset (Response F r w n 1))
    (receivedProximity receivedLinear receivedQuadratic : Word F n)
    (hvalid : ∀ response ∈ responses, response.Valid C)
    (hagrees : ∀ response ∈ responses, agreement ≤
      (schemeJointAgreement receivedProximity receivedLinear receivedQuadratic
        response).card)
    {responseDistance : ℕ}
    (hresponse : HasMinimumDistanceAtLeast C.responseCode responseDistance)
    (hresponseRadius : n - agreement < responseDistance)
    (hresponseDen : 0 <
      InterleavedJohnson.denominator n responseDistance (n - agreement)) :
    responses.card ≤
      InterleavedJohnson.listBound n responseDistance (n - agreement) := by
  classical
  let received := schemeReceivedMatrix receivedProximity receivedLinear
    receivedQuadratic
  let matrices := responses.image
    (schemeMatrix (F := F) (r := r) (w := w) (n := n))
  have hresponses : responses.card ≤ matrices.card := by
    apply Finset.card_le_card_of_injOn
      (schemeMatrix (F := F) (r := r) (w := w) (n := n))
    · intro response hresponse
      exact Finset.mem_image.mpr ⟨response, hresponse, rfl⟩
    · exact schemeMatrix_injOn_valid C h2k responses hvalid
  have hcode (candidate : Fin 3 → Word F n) (hcandidate : candidate ∈ matrices)
      (row : Fin 3) : candidate row ∈ C.responseCode := by
    obtain ⟨response, hresponse, rfl⟩ := Finset.mem_image.mp hcandidate
    have hv := hvalid response hresponse 0
    fin_cases row
    · exact baseCode_le_responseCode C (C.codeword_mem_baseCode hv.1)
    · exact C.codeword_mem_responseCode hv.2.1
    · exact C.codeword_mem_responseCode hv.2.2
  have hclose (candidate : Fin 3 → Word F n) (hcandidate : candidate ∈ matrices) :
      (matrixErrorCoordinates received candidate).card ≤ n - agreement := by
    obtain ⟨response, hresponse, rfl⟩ := Finset.mem_image.mp hcandidate
    rw [matrixErrorCoordinates_schemeMatrix]
    rw [Finset.card_sdiff]
    simpa using Nat.sub_le_sub_left (hagrees response hresponse) n
  exact hresponses.trans (InterleavedJohnson.card_le_listBound C.responseCode
    received matrices hresponse hcode hclose (Nat.sub_le n agreement)
      hresponseRadius hresponseDen)


variable {Equations CheckedMask DirectMask : Type*}
variable [Fintype Equations] [Fintype CheckedMask]
variable {nw nq : ℕ}

/-- The full committed word tested by the scheme linear check. -/
noncomputable def schemeLinearObserved
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (weights : Equations → F) : Word F n := fun j =>
  (∑ block : CoreBlock,
      ∑ row : Fin (block.rowCount nw nq),
        Verifier.coefficientRow C statement weights block row (codePosition j) *
          oracle.core block row j) +
    scheme.linearAt (codePosition j)
      (fun mask => oracle.checkedMask 0 mask j)
      (fun mask => oracle.directMask 0 mask j)

/-- The full committed word tested by the scheme quadratic check. -/
noncomputable def schemeQuadraticObserved
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (weights : Fin nq → F) : Word F n := fun j =>
  (∑ row : Fin nq, weights row *
      (oracle.core .left row j * oracle.core .right row j -
        oracle.core .output row j)) +
    scheme.quadraticAt (codePosition j)
      (fun mask => oracle.checkedMask 0 mask j)
      (fun mask => oracle.directMask 0 mask j)



noncomputable def schemeAcceptingCoordinates
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (response : Response F r w n 1) : Finset (Fin n) :=
  agreementCoordinates (schemeProximityObserved oracle (challenge 0).proximity)
      (response.codewords.proximity 0) ∩
    agreementCoordinates
      (schemeLinearObserved C scheme statement oracle (challenge 0).linear)
      (response.codewords.linear 0) ∩
    agreementCoordinates
      (schemeQuadraticObserved scheme oracle (challenge 0).quadratic)
      (response.codewords.quadratic 0)



theorem scheme_query_subset_acceptingCoordinates_of_accepts
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (response : Response F r w n 1) (query : QuerySet n r)
    (haccept : SchemeVerifier.Accepts C scheme statement challenge response query
      (openSchemeOracle oracle query)) :
    query.coordinates ⊆
      schemeAcceptingCoordinates C scheme statement oracle challenge response := by
  intro j hj
  have hprox := (haccept 0).1.2 ⟨j, hj⟩
  have hlinear := (haccept 0).2.1.2.2 ⟨j, hj⟩
  have hquadratic := (haccept 0).2.2.2.2 ⟨j, hj⟩
  simp only [schemeAcceptingCoordinates, Finset.mem_inter,
    agreementCoordinates, Finset.mem_filter, Finset.mem_univ, true_and]
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · simpa [schemeProximityObserved, Response.codewords, codeword,
      openSchemeOracle, SchemeOracle.column, SchemeOracle.testedRow] using hprox.symm
  · simpa [schemeLinearObserved, Response.codewords, codeword,
      openSchemeOracle, SchemeOracle.column] using hlinear.symm
  · simpa [schemeQuadraticObserved, Response.codewords, codeword,
      openSchemeOracle, SchemeOracle.column] using hquadratic.symm

/-- The common accepting set is contained in each component agreement set. -/
theorem scheme_acceptingCoordinates_component_agreement
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (response : Response F r w n 1) {agreement : ℕ}
    (hagreement : agreement ≤
      (schemeAcceptingCoordinates C scheme statement oracle challenge response).card) :
    agreement ≤ (agreementCoordinates
        (schemeProximityObserved oracle (challenge 0).proximity)
        (response.codewords.proximity 0)).card ∧
      agreement ≤ (agreementCoordinates
        (schemeLinearObserved C scheme statement oracle (challenge 0).linear)
        (response.codewords.linear 0)).card ∧
      agreement ≤ (agreementCoordinates
        (schemeQuadraticObserved scheme oracle (challenge 0).quadratic)
        (response.codewords.quadratic 0)).card := by
  let proximity : Finset (Fin n) := agreementCoordinates
    (schemeProximityObserved oracle (challenge 0).proximity)
    (response.codewords.proximity 0)
  let linear : Finset (Fin n) := agreementCoordinates
    (schemeLinearObserved C scheme statement oracle (challenge 0).linear)
    (response.codewords.linear 0)
  let quadratic : Finset (Fin n) := agreementCoordinates
    (schemeQuadraticObserved scheme oracle (challenge 0).quadratic)
    (response.codewords.quadratic 0)
  change agreement ≤ ((proximity ∩ linear) ∩ quadratic).card at hagreement
  change agreement ≤ proximity.card ∧ agreement ≤ linear.card ∧
    agreement ≤ quadratic.card
  exact ⟨hagreement.trans (Finset.card_le_card
      (Finset.inter_subset_left.trans Finset.inter_subset_left)),
    hagreement.trans (Finset.card_le_card
      (Finset.inter_subset_left.trans Finset.inter_subset_right)),
    hagreement.trans (Finset.card_le_card Finset.inter_subset_right)⟩



theorem schemeAcceptedResponses_card_le
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (responses : Finset (Response F r w n 1))
    (haccepted : ∀ response ∈ responses, ∃ query : QuerySet n r,
      SchemeVerifier.Accepts C scheme statement challenge response query
        (openSchemeOracle oracle query))
    (hagreement : ∀ response ∈ responses, agreement ≤
      (schemeAcceptingCoordinates C scheme statement oracle challenge response).card)
    (hbase : HasMinimumDistanceAtLeast C.baseCode d)
    {responseDistance : ℕ}
    (hresponse : HasMinimumDistanceAtLeast C.responseCode responseDistance)
    (hbaseRadius : n - agreement < d)
    (hresponseRadius : n - agreement < responseDistance)
    (hbaseDen : 0 < InterleavedJohnson.denominator n d (n - agreement))
    (hresponseDen : 0 <
      InterleavedJohnson.denominator n responseDistance (n - agreement)) :
    responses.card ≤
      InterleavedJohnson.listBound n d (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement) := by
  apply schemeResponses_card_le C h2k responses
    (schemeProximityObserved oracle (challenge 0).proximity)
    (schemeLinearObserved C scheme statement oracle (challenge 0).linear)
    (schemeQuadraticObserved scheme oracle (challenge 0).quadratic)
  · intro response hresponseMem
    obtain ⟨query, haccept⟩ := haccepted response hresponseMem
    exact SchemeVerifier.valid_of_accepts C scheme statement challenge response query
      (openSchemeOracle oracle query) haccept
  · intro response hresponseMem
    exact scheme_acceptingCoordinates_component_agreement C scheme statement oracle
      challenge response (hagreement response hresponseMem)
  · exact hbase
  · exact hresponse
  · exact hbaseRadius
  · exact hresponseRadius
  · exact hbaseDen
  · exact hresponseDen




noncomputable def schemeListedResponses
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (agreement : ℕ) : Finset (Response F r w n 1) := by
  classical
  exact Finset.univ.filter fun response ↦
    (∃ query : QuerySet n r,
      SchemeVerifier.Accepts C scheme statement challenge response query
        (openSchemeOracle oracle query)) ∧
    agreement ≤
      (schemeAcceptingCoordinates C scheme statement oracle challenge response).card



theorem schemeListedResponses_card_le
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (agreement : ℕ)
    (hbase : HasMinimumDistanceAtLeast C.baseCode d)
    {responseDistance : ℕ}
    (hresponse : HasMinimumDistanceAtLeast C.responseCode responseDistance)
    (hbaseRadius : n - agreement < d)
    (hresponseRadius : n - agreement < responseDistance)
    (hbaseDen : 0 < InterleavedJohnson.denominator n d (n - agreement))
    (hresponseDen : 0 <
      InterleavedJohnson.denominator n responseDistance (n - agreement)) :
    (schemeListedResponses C scheme statement oracle challenge agreement).card ≤
      InterleavedJohnson.listBound n d (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement) *
      InterleavedJohnson.listBound n responseDistance (n - agreement) := by
  classical
  apply schemeAcceptedResponses_card_le C h2k scheme statement oracle challenge
  · intro response hresponseMem
    have h : (∃ query : QuerySet n r,
        SchemeVerifier.Accepts C scheme statement challenge response query
          (openSchemeOracle oracle query)) ∧
        agreement ≤ (schemeAcceptingCoordinates C scheme statement oracle
          challenge response).card := by
      simpa [schemeListedResponses] using hresponseMem
    exact h.1
  · intro response hresponseMem
    have h : (∃ query : QuerySet n r,
        SchemeVerifier.Accepts C scheme statement challenge response query
          (openSchemeOracle oracle query)) ∧
        agreement ≤ (schemeAcceptingCoordinates C scheme statement oracle
          challenge response).card := by
      simpa [schemeListedResponses] using hresponseMem
    exact h.2
  · exact hbase
  · exact hresponse
  · exact hbaseRadius
  · exact hresponseRadius
  · exact hbaseDen
  · exact hresponseDen



theorem schemeListedResponses_card_le_interleaved
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (agreement : ℕ) {responseDistance : ℕ}
    (hresponse : HasMinimumDistanceAtLeast C.responseCode responseDistance)
    (hresponseRadius : n - agreement < responseDistance)
    (hresponseDen : 0 <
      InterleavedJohnson.denominator n responseDistance (n - agreement)) :
    (schemeListedResponses C scheme statement oracle challenge agreement).card ≤
      InterleavedJohnson.listBound n responseDistance (n - agreement) := by
  classical
  apply schemeResponses_card_le_interleaved C h2k
    (schemeListedResponses C scheme statement oracle challenge agreement)
    (schemeProximityObserved oracle (challenge 0).proximity)
    (schemeLinearObserved C scheme statement oracle (challenge 0).linear)
    (schemeQuadraticObserved scheme oracle (challenge 0).quadratic)
  · intro response hresponseMem
    have h := (Finset.mem_filter.mp hresponseMem).2.1
    obtain ⟨query, haccept⟩ := h
    exact SchemeVerifier.valid_of_accepts C scheme statement challenge response
      query (openSchemeOracle oracle query) haccept
  · intro response hresponseMem
    have h := (Finset.mem_filter.mp hresponseMem).2.2
    simpa [schemeAcceptingCoordinates, schemeJointAgreement] using h
  · exact hresponse
  · exact hresponseRadius
  · exact hresponseDen

/-! ### Threshold-free response-agreement lists -/

/-- Canonical response list at one exact response-agreement level.  Agreement
is measured by the union of coordinates occurring in actually accepting
queries, so it is simultaneously controlled by every soundness-classifier
cover and by the response-code agreement set. -/
noncomputable def schemeResponseAgreementList
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (agreement : ℕ) : Finset (Response F r w n 1) := by
  classical
  exact Finset.univ.filter fun response ↦
    (∃ query : QuerySet n r,
      SchemeVerifier.Accepts C scheme statement challenge response query
        (openSchemeOracle oracle query)) ∧
    agreement ≤ (policyAcceptingCoordinates
      (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
        (repetitions := 1) C scheme)
      oracle statement challenge response).card

theorem schemeResponseAgreementList_eq_policy
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (agreement : ℕ) :
    schemeResponseAgreementList C scheme statement oracle challenge agreement =
      policyResponseAgreementList
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C scheme)
        oracle statement challenge agreement := by
  rfl

theorem scheme_policyAcceptingCoordinates_subset_joint
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (response : Response F r w n 1) :
    policyAcceptingCoordinates
        (SchemeVerifier.policy (Equations := Equations) (nw := nw) (nq := nq)
          (repetitions := 1) C scheme)
        oracle statement challenge response ⊆
      schemeAcceptingCoordinates C scheme statement oracle challenge response := by
  classical
  intro coordinate hcoordinate
  obtain ⟨query, haccept, hmem⟩ :=
    (Finset.mem_filter.mp hcoordinate).2
  exact scheme_query_subset_acceptingCoordinates_of_accepts
    C scheme statement oracle challenge response query haccept hmem

/-- Pointwise one-interleaved Johnson theorem for the actual response-
agreement list.  This is the multiplicity theorem used at every layer-cake
level; no endpoint monotonicity or threshold formula is assumed. -/
theorem schemeResponseAgreementList_card_le_interleaved
    (C : MultiplicativeCode F r w n) (h2k : 2 * C.k ≤ n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (agreement : ℕ) {responseDistance : ℕ}
    (hresponse : HasMinimumDistanceAtLeast C.responseCode responseDistance)
    (hresponseRadius : n - agreement < responseDistance)
    (hresponseDen : 0 <
      InterleavedJohnson.denominator n responseDistance (n - agreement)) :
    (schemeResponseAgreementList C scheme statement oracle challenge agreement).card
      ≤ InterleavedJohnson.listBound n responseDistance
        (n - agreement) := by
  classical
  apply schemeResponses_card_le_interleaved C h2k
    (schemeResponseAgreementList C scheme statement oracle challenge agreement)
    (schemeProximityObserved oracle (challenge 0).proximity)
    (schemeLinearObserved C scheme statement oracle (challenge 0).linear)
    (schemeQuadraticObserved scheme oracle (challenge 0).quadratic)
  · intro response hresponseMem
    obtain ⟨query, haccept⟩ := (Finset.mem_filter.mp hresponseMem).2.1
    exact SchemeVerifier.valid_of_accepts C scheme statement challenge response
      query (openSchemeOracle oracle query) haccept
  · intro response hresponseMem
    have hagreement := (Finset.mem_filter.mp hresponseMem).2.2
    exact hagreement.trans (Finset.card_le_card
      (scheme_policyAcceptingCoordinates_subset_joint C scheme statement oracle
        challenge response))
  · exact hresponse
  · exact hresponseRadius
  · exact hresponseDen





theorem scheme_acceptingCoordinates_card_le_of_not_mem_listed
    (C : MultiplicativeCode F r w n)
    (scheme : MaskScheme F CheckedMask DirectMask r w n)
    (statement : ConstraintSystem F nw nq w Equations)
    (oracle : SchemeOracle F CheckedMask DirectMask nw nq n 1)
    (challenge : SchemeChallenge F CheckedMask nw nq 1 Equations)
    (response : Response F r w n 1) (query : QuerySet n r)
    (floor : ℕ)
    (haccept : SchemeVerifier.Accepts C scheme statement challenge response query
      (openSchemeOracle oracle query))
    (hnot : response ∉
      schemeListedResponses C scheme statement oracle challenge (floor + 1)) :
    (schemeAcceptingCoordinates C scheme statement oracle challenge
      response).card ≤ floor := by
  by_contra hlarge
  apply hnot
  simp only [schemeListedResponses, Finset.mem_filter, Finset.mem_univ,
    true_and]
  exact ⟨⟨query, haccept⟩, by omega⟩



variable {q : ℕ}


end LigeroFamily.RigidResponseList
