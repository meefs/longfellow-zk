import Ligero.API
import AffineAgreement
import CorrelatedAgreement
import SelectedMCA
import CodingTheory.ListDecoding

/-! Compile-time checks for the clean-break Ligero public surface. -/

-- Mask-independent architecture.
#guard_msgs (drop info) in #check AffineAgreement.DecoderData
#guard_msgs (drop info) in #check AffineAgreement.affineCodewordLine_of_common_agreement
#guard_msgs (drop info) in #check CorrelatedAgreement.correlated_agreement
#guard_msgs (drop info) in #check CorrelatedAgreement.correlated_agreement_of_decoderData
#guard_msgs (drop info) in #check SelectedMCA.directionallyNonliftableParameters_card_le_direct
#guard_msgs (drop info) in #check SelectedMCA.directionallyNonliftableParameters_card_lt_direct
#guard_msgs (drop info) in #check SelectedMCA.directionallyNonliftableParameters_card_le_of_three_radius
#guard_msgs (drop info) in #check CodingTheory.InterleavedJohnson.card_le_listBound
#guard_msgs (drop info) in #check LigeroFamily.SelectedMCAParameterConditions
#guard_msgs (drop info) in #check LigeroFamily.DirectMCAConditions
#guard_msgs (drop info) in #check LigeroFamily.PuncturedGlobalizationConditions
#guard_msgs (drop info) in #check LigeroFamily.JohnsonListConditions
#guard_msgs (drop info) in #check LigeroFamily.MultiplicativeCode
#guard_msgs (drop info) in #check LigeroFamily.MultiplicativeCode.MaskingBasis
#guard_msgs (drop info) in #check LigeroFamily.MultiplicativeCode.query_le_length
#guard_msgs (drop info) in #check LigeroFamily.MaskingRateCondition
#guard_msgs (drop info) in #check LigeroFamily.CoreMessages
#guard_msgs (drop info) in #check LigeroFamily.ConstraintSystem
#guard_msgs (drop info) in #check LigeroFamily.Response
#guard_msgs (drop info) in #check LigeroFamily.MaskScheme
#guard_msgs (drop info) in #check LigeroFamily.SchemeOracle
#guard_msgs (drop info) in #check LigeroFamily.schemeOracleEquivColumns
#guard_msgs (drop info) in #check LigeroFamily.openSchemeOracle_congr
#guard_msgs (drop info) in #check LigeroFamily.SchemeChallenge
#guard_msgs (drop info) in #check LigeroFamily.SchemeVerifier.protocol
#guard_msgs (drop info) in #check LigeroFamily.SchemeLiftCandidate
#guard_msgs (drop info) in #check LigeroFamily.PolicyLiftListCertificate
#guard_msgs (drop info) in #check LigeroFamily.SchemeGLiftWitness
#guard_msgs (drop info) in #check LigeroFamily.PolicyArithmeticCertificate.doublyProfiledClassifier_nonempty
#guard_msgs (drop info) in #check LigeroFamily.SchemeProtocolPolicy
#guard_msgs (drop info) in #check LigeroFamily.SchemeExtractorPolicy
#guard_msgs (drop info) in #check LigeroFamily.schemeExtractorPolicy
#guard_msgs (drop info) in #check LigeroFamily.ReedSolomon.Domain
#guard_msgs (drop info) in #check LigeroFamily.ReedSolomon.multiplicativeCode
#guard_msgs (drop info) in #check LigeroFamily.ReedSolomon.baseCode_minimum_distance
#guard_msgs (drop info) in #check Ligero.V1.EndToEndGuarantee
#guard_msgs (drop info) in #check Ligero.V1.EndToEndGuarantee.perfectCompleteness
#guard_msgs (drop info) in #check Ligero.V1.EndToEndGuarantee.soundness
#guard_msgs (drop info) in #check Ligero.V1.EndToEndGuarantee.extraction
#guard_msgs (drop info) in #check Ligero.V1.EndToEndGuarantee.zeroKnowledge
#guard_msgs (drop info) in #check LigeroFamily.ConstraintSystem.residual_of_not_satisfies
#guard_msgs (drop info) in #check LigeroFamily.SchemeLiftCandidate.residual_of_not_satisfies
#guard_msgs (drop info) in #check LigeroFamily.NoDecodedSolution
#guard_msgs (drop info) in #check LigeroFamily.NoDecodedSolution.of_not_language
#guard_msgs (drop info) in #check LigeroFamily.liftListIndex
#guard_msgs (drop info) in #check LigeroFamily.exists_liftListIndex
#guard_msgs (drop info) in #check LigeroFamily.SchemeLiftCandidate.univ_card_le_listBound
#guard_msgs (drop info) in #check Ligero.V1.candidate_of_acceptance
#guard_msgs (drop info) in #check Ligero.V1.witness_extractor
#guard_msgs (drop info) in
  #check LigeroFamily.PolicyDoublyProfiledSoundnessClassifier.DoomedAfter
#guard_msgs (drop info) in
  #check LigeroFamily.PolicyDoublyProfiledSoundnessClassifier.escaping
#guard_msgs (drop info) in
  #check LigeroFamily.PolicyDoublyProfiledSoundnessClassifier.query_density_le_of_doomedAfter
#guard_msgs (drop info) in
  #check LigeroFamily.PolicyDoublyProfiledSoundnessClassifier.escaping_density_le
#guard_msgs (drop info) in #check Ligero.V1.Mask
#guard_msgs (drop info) in #check Ligero.V1.Scheme
#guard_msgs (drop info) in #check Ligero.V1.Oracle
#guard_msgs (drop info) in #check Ligero.V1.Challenge
#guard_msgs (drop info) in #check Ligero.V1.Opening
#guard_msgs (drop info) in #check Ligero.V1.V1ProverRandomness
#guard_msgs (drop info) in #check Ligero.V1.V1Violation
#guard_msgs (drop info) in #check Ligero.V1.V1JohnsonRange
#guard_msgs (drop info) in #check Ligero.V1.v1_ligero_perfect_completeness
#guard_msgs (drop info) in #check Ligero.V1.v1_ligero_soundness_selectedMCA
#guard_msgs (drop info) in #check Ligero.V1.v1_ligero_soundness_of_profiledFailure
#guard_msgs (drop info) in #check Ligero.V1.ZeroKnowledge.v1_unbounded_perfect_response_adaptive_zero_knowledge

-- New Ligero: four checked base-code mask kinds.
#guard_msgs (drop info) in #check Ligero.V1.ReedSolomon.end_to_end_selectedMCA
#guard_msgs (drop info) in #print axioms LigeroFamily.ConstraintSystem.residual_of_not_satisfies
#guard_msgs (drop info) in #print axioms LigeroFamily.NoDecodedSolution.of_not_language
#guard_msgs (drop info) in #print axioms LigeroFamily.exists_liftListIndex
#guard_msgs (drop info) in #print axioms LigeroFamily.SchemeLiftCandidate.univ_card_le_listBound
#guard_msgs (drop info) in #print axioms Ligero.V1.witness_extractor
#guard_msgs (drop info) in #print axioms Ligero.V1.end_to_end_selectedMCA
