import AffineAgreement.Basic

/-! Selected decoder data shared by affine agreement arguments. -/

namespace AffineAgreement

variable {F : Type*} [Field F] [DecidableEq F]

/-- Exactly `m` distinct parameters with a selected radius-`e` decoder. -/
structure DecoderData {n e m : ℕ} (C : LinearCode F n)
    (u v : Word F n) where
  parameters : Finset F
  decoder : parameters → Word F n
  card_parameters : parameters.card = m
  decoder_mem : ∀ t, decoder t ∈ C
  decoder_near : ∀ t,
    weight (affineWord u v t.1 - decoder t) ≤ e

namespace DecoderData

variable {n e m : ℕ} {C : LinearCode F n} {u v : Word F n}

/-- Totalized selected codeword, equal to zero away from the parameter set. -/
def codeword (D : DecoderData (e := e) (m := m) C u v) (t : F) : Word F n :=
  if ht : t ∈ D.parameters then D.decoder ⟨t, ht⟩ else 0

theorem codeword_eq (D : DecoderData (e := e) (m := m) C u v) {t : F}
    (ht : t ∈ D.parameters) : D.codeword t = D.decoder ⟨t, ht⟩ := by
  simp [codeword, ht]

theorem codeword_mem (D : DecoderData (e := e) (m := m) C u v) {t : F}
    (ht : t ∈ D.parameters) : D.codeword t ∈ C := by
  rw [D.codeword_eq ht]
  exact D.decoder_mem _

theorem error_card (D : DecoderData (e := e) (m := m) C u v) {t : F}
    (ht : t ∈ D.parameters) :
    weight (affineWord u v t - D.codeword t) ≤ e := by
  simpa [codeword, ht] using D.decoder_near ⟨t, ht⟩

/-- Restrict selected decoder data to a prescribed subset of its parameters. -/
noncomputable def restrict (D : DecoderData (e := e) (m := m) C u v)
    {k : ℕ} (parameters : Finset F) (hparameters : parameters ⊆ D.parameters)
    (hcard : parameters.card = k) : DecoderData (e := e) (m := k) C u v := {
  parameters := parameters
  decoder := fun scalar ↦ D.codeword scalar.1
  card_parameters := hcard
  decoder_mem := fun scalar ↦ D.codeword_mem (hparameters scalar.2)
  decoder_near := fun scalar ↦ D.error_card (hparameters scalar.2) }

@[simp] theorem restrict_parameters
    (D : DecoderData (e := e) (m := m) C u v)
    {k : ℕ} (parameters : Finset F) (hparameters : parameters ⊆ D.parameters)
    (hcard : parameters.card = k) :
    (D.restrict parameters hparameters hcard).parameters = parameters := rfl

/-- Restriction preserves the selected codeword at retained parameters. -/
theorem restrict_codeword_eq
    (D : DecoderData (e := e) (m := m) C u v)
    {k : ℕ} (parameters : Finset F) (hparameters : parameters ⊆ D.parameters)
    (hcard : parameters.card = k) {scalar : F} (hscalar : scalar ∈ parameters) :
    (D.restrict parameters hparameters hcard).codeword scalar =
      D.codeword scalar := by
  simp [codeword, restrict, hscalar]

end DecoderData

end AffineAgreement
