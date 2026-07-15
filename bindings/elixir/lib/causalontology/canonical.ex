defmodule Causalontology.Canonical do
  @moduledoc """
  Canonicalization and content-addressed identity.

  Implements the identity procedure of spec/identity.md:
    1. take the object as JSON,
    2. keep only the identity-bearing fields for its kind (with "type" injected),
    3. serialize with the JSON Canonicalization Scheme (RFC 8785),
    4. hash with SHA-256,
    5. identifier = scheme + ":" + lowercase hex digest.
  """

  alias Causalontology.Jcs

  @identity_fields %{
    "occurrent" => ["label", "category"],
    "causal_relation_object" => ["causes", "effects", "mechanism", "temporal", "modality", "context", "refines"],
    "continuant" => ["label", "category"],
    "realizable" => ["kind", "bearer"],
    "assertion" => [
      "about",
      "source",
      "evidence_type",
      "evidence",
      "strength",
      "confidence",
      "timestamp"
    ],
    "enrichment" => ["about", "field", "entry", "source", "timestamp"],
    "retraction" => ["retracts", "source", "timestamp"],
    "succession" => ["predecessor", "successor", "timestamp"]
  }

  @prefix %{
    "occurrent" => "occurrent",
    "causal_relation_object" => "causal_relation_object",
    "continuant" => "continuant",
    "realizable" => "realizable",
    "assertion" => "assertion",
    "enrichment" => "enrichment",
    "retraction" => "retraction",
    "succession" => "succession"
  }

  @kind_of_prefix Map.new(@prefix, fn {kind, prefix} -> {prefix, kind} end)

  @doc "The kind -> identifier-scheme prefix table."
  def prefix, do: @prefix

  @doc "The identifier-scheme prefix -> kind table."
  def kind_of_prefix, do: @kind_of_prefix

  @doc "Infer an object's kind from its type field, id prefix, or shape."
  def infer_kind(obj) when is_map(obj) do
    id = Map.get(obj, "id")

    cond do
      Map.has_key?(obj, "type") ->
        Map.fetch!(obj, "type")

      is_binary(id) and String.contains?(id, ":") and kind_from_id(id) != nil ->
        kind_from_id(id)

      Map.has_key?(obj, "causes") and Map.has_key?(obj, "effects") ->
        "causal_relation_object"

      Map.has_key?(obj, "retracts") ->
        "retraction"

      Map.has_key?(obj, "predecessor") and Map.has_key?(obj, "successor") ->
        "succession"

      Map.has_key?(obj, "field") and Map.has_key?(obj, "entry") ->
        "enrichment"

      Map.has_key?(obj, "evidence_type") or
          (Map.has_key?(obj, "about") and Map.has_key?(obj, "confidence")) ->
        "assertion"

      Map.has_key?(obj, "kind") and Map.has_key?(obj, "bearer") ->
        "realizable"

      true ->
        raise ArgumentError,
              "cannot infer kind (occurrents and continuants share a shape); " <>
                "pass kind explicitly"
    end
  end

  defp kind_from_id(id) do
    Map.get(@kind_of_prefix, id |> String.split(":", parts: 2) |> hd())
  end

  @doc "The identity-bearing subset of an object, with type always present."
  def identity_bearing(obj, kind \\ nil) do
    kind = kind || infer_kind(obj)

    fields =
      Map.get(@identity_fields, kind) ||
        raise(ArgumentError, "unknown kind: #{inspect(kind)}")

    subset =
      Enum.reduce(fields, %{"type" => kind}, fn field, acc ->
        if Map.has_key?(obj, field), do: Map.put(acc, field, Map.fetch!(obj, field)), else: acc
      end)

    {kind, subset}
  end

  @doc "The RFC 8785 identity-bearing bytes of an object."
  def canonicalize(obj, kind \\ nil) do
    {_kind, subset} = identity_bearing(obj, kind)
    Jcs.encode(subset)
  end

  @doc "The content-addressed identifier: scheme + ':' + SHA-256 hex."
  def identify(obj, kind \\ nil) do
    {kind, subset} = identity_bearing(obj, kind)
    digest = :crypto.hash(:sha256, Jcs.encode(subset)) |> Base.encode16(case: :lower)
    Map.fetch!(@prefix, kind) <> ":" <> digest
  end
end
