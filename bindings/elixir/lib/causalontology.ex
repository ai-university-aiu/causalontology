defmodule Causalontology do
  @moduledoc """
  causalontology - the Elixir binding of the Causalontology standard.

  A faithful port of causalontology-py, sharing the same conformance suite:
  OTP standard library only (`:crypto` for SHA-256 and Ed25519), conformant
  when it passes every vector in conformance/vectors/ (run
  `elixir conformance.exs` from bindings/elixir).

  Causalontology is a verb-first noun-hosting ontology: reality is what
  happens, and things are its participants.
  """

  @version "4.0.0"

  @doc "The binding version (specification 4.0.0: attitude, predicted_occurrence, prediction_error)."
  def version, do: @version

  # Canonicalization and identity.
  defdelegate canonicalize(obj, kind \\ nil), to: Causalontology.Canonical
  defdelegate identify(obj, kind \\ nil), to: Causalontology.Canonical
  defdelegate identity_bearing(obj, kind \\ nil), to: Causalontology.Canonical
  defdelegate infer_kind(obj), to: Causalontology.Canonical

  # Schema and semantics validation.
  defdelegate validate_schema(obj, kind \\ nil), to: Causalontology.Schema
  defdelegate validate_semantics(obj, kind \\ nil), to: Causalontology.Semantics
  defdelegate is_partial(cro), to: Causalontology.Semantics
  defdelegate admissible(cro, elapsed_seconds), to: Causalontology.Semantics
  defdelegate conflicts(a, b), to: Causalontology.Semantics
  defdelegate refinement_valid(child, parent), to: Causalontology.Semantics
  defdelegate hierarchy_consistent(parent, members), to: Causalontology.Semantics

  # Signing.
  defdelegate keypair_from_seed(seed32), to: Causalontology.Signing
  defdelegate sign_record(record, secret, kind \\ nil), to: Causalontology.Signing
  defdelegate verify_record(record, kind \\ nil), to: Causalontology.Signing
end
