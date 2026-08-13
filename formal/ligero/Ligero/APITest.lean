import Ligero.API
import AffineAgreement
import CorrelatedAgreement
import SelectedMCA
import CodingTheory.ListDecoding

/-! Compile-time checks for the clean-break Ligero public surface. -/

-- Mask-independent architecture.
#check AffineAgreement.DecoderData
#check AffineAgreement.affineCodewordLine_of_common_agreement
#check CorrelatedAgreement.correlated_agreement
#check CorrelatedAgreement.correlated_agreement_of_decoderData
#check SelectedMCA.directionallyNonliftableParameters_card_le_direct
#check SelectedMCA.directionallyNonliftableParameters_card_lt_direct
#check SelectedMCA.directionallyNonliftableParameters_card_le_of_three_radius
#check CodingTheory.InterleavedJohnson.card_le_listBound
#check Ligero.Common.SelectedMCAParameterConditions
#check Ligero.Common.DirectMCAConditions
#check Ligero.Common.PuncturedGlobalizationConditions
#check Ligero.Common.JohnsonListConditions
#check Ligero.Common.MultiplicativeCode
#check Ligero.Common.MultiplicativeCode.MaskingBasis
#check Ligero.Common.MultiplicativeCode.query_le_length
#check Ligero.Common.MaskingRateCondition
#check Ligero.Common.CoreMessages
#check Ligero.Common.ConstraintSystem
#check Ligero.Common.Response
#check Ligero.Common.MaskScheme
#check Ligero.Common.SchemeOracle
#check Ligero.Common.SchemeChallenge
#check Ligero.Common.SchemeVerifier.protocol
#check Ligero.Common.SchemeLiftCandidate
#check Ligero.Common.PolicyLiftListCertificate
#check Ligero.Common.SchemeGLiftWitness
#check Ligero.Common.PolicyArithmeticCertificate.doublyProfiledClassifier_nonempty
#check Ligero.Common.SchemeProtocolPolicy
#check Ligero.Common.SchemeExtractorPolicy
#check Ligero.Common.schemeExtractorPolicy
#check Ligero.Common.ReedSolomon.Domain
#check Ligero.Common.ReedSolomon.multiplicativeCode
#check Ligero.Common.ReedSolomon.baseCode_minimum_distance
#check Ligero.Common.V1EndToEndGuarantee
#check Ligero.Common.V1EndToEndGuarantee.perfectCompleteness
#check Ligero.Common.V1EndToEndGuarantee.soundness
#check Ligero.Common.V1EndToEndGuarantee.zeroKnowledge
#check Ligero.MaskV1.Mask
#check Ligero.MaskV1.Scheme
#check Ligero.MaskV1.Oracle
#check Ligero.MaskV1.Challenge
#check Ligero.MaskV1.Opening
#check Ligero.MaskV1.V1ProverRandomness
#check Ligero.MaskV1.V1Violation
#check Ligero.MaskV1.V1JohnsonRange
#check Ligero.MaskV1.v1_ligero_perfect_completeness
#check Ligero.MaskV1.v1_ligero_soundness_selectedMCA
#check Ligero.MaskV1.v1_ligero_soundness_of_profiledFailure
#check Ligero.MaskV1.ZeroKnowledge.v1_unbounded_perfect_response_adaptive_zero_knowledge

-- New Ligero: four checked base-code mask kinds.
