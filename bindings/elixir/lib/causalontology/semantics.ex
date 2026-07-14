defmodule Causalontology.Semantics do
  @moduledoc """
  The semantic rules beyond the schemas (spec/semantics.md).

  Local rules are checked here; store-context rules (materialized acyclicity,
  retraction lineage) live in `Causalontology.Store` where the context exists.
  """

  alias Causalontology.Canonical

  # Rule 4: the fixed unit-conversion constants (average Gregorian values).
  @unit_seconds %{
    "instant" => 0,
    "seconds" => 1,
    "minutes" => 60,
    "hours" => 3600,
    "days" => 86_400,
    "weeks" => 604_800,
    "months" => 2_629_746,
    "years" => 31_556_952
  }

  # Rule 12: enrichment field-to-kind validity and entry shapes.
  @enrichment_fields %{
    "aliases" => {["occurrent", "continuant"], "alias"},
    "participants" => {["occurrent"], "cnt"},
    "subsumes" => {["continuant"], "cnt"},
    "part_of" => {["continuant"], "cnt"},
    "realized_in" => {["realizable"], "occ"}
  }

  @cro_optional_fields ["mechanism", "temporal", "modality", "context"]

  @positive_modalities ["necessary", "sufficient", "contributory"]

  @doc "The fixed unit-to-seconds conversion table (rule 4)."
  def unit_seconds, do: @unit_seconds

  @doc "The enrichment field-to-kind/entry-shape table (rule 12)."
  def enrichment_fields, do: @enrichment_fields

  @doc "The four optional CRO fields, in canonical order."
  def cro_optional_fields, do: @cro_optional_fields

  @doc "{ok, reasons} — the locally checkable semantic rules."
  def validate_semantics(obj, kind \\ nil) do
    kind = kind || Canonical.infer_kind(obj)

    errors =
      case kind do
        "cro" -> cro_errors(obj)
        "enrichment" -> enrichment_errors(obj)
        _ -> []
      end

    {errors == [], errors}
  end

  defp cro_errors(obj) do
    temporal = Map.get(obj, "temporal")
    oid = Map.get(obj, "id")
    errors = []

    errors =
      if is_map(temporal) and Map.get(temporal, "dmin") != nil and
           Map.get(temporal, "dmax") != nil and
           Map.fetch!(temporal, "dmin") > Map.fetch!(temporal, "dmax") do
        errors ++ ["dmin must be <= dmax"]
      else
        errors
      end

    errors =
      if oid != nil and oid in Map.get(obj, "mechanism", []) do
        errors ++
          ["mechanism must be acyclic (a Causal Relation Object may not contain itself)"]
      else
        errors
      end

    if oid != nil and Map.get(obj, "refines") == oid do
      errors ++ ["refines must be acyclic"]
    else
      errors
    end
  end

  defp enrichment_errors(obj) do
    field = Map.get(obj, "field")
    about = Map.get(obj, "about", "")
    entry = Map.get(obj, "entry")

    case Map.get(@enrichment_fields, field) do
      nil ->
        []

      {legal_kinds, shape} ->
        about_kind = kind_of_id(about)

        errors =
          if about_kind != nil and about_kind not in legal_kinds do
            ["#{field} is not a legal field for a #{about_kind} (rule 12)"]
          else
            []
          end

        if shape == "alias" do
          if is_map(entry) and Map.has_key?(entry, "lang") and Map.has_key?(entry, "text") do
            errors
          else
            errors ++ ["an aliases entry must be a language-tagged text object"]
          end
        else
          if is_binary(entry) and String.starts_with?(entry, shape <> ":") do
            errors
          else
            errors ++ ["a #{field} entry must be a #{shape}: identifier"]
          end
        end
    end
  end

  defp kind_of_id(identifier) when is_binary(identifier) do
    Map.get(Canonical.kind_of_prefix(), identifier |> String.split(":", parts: 2) |> hd())
  end

  defp kind_of_id(_identifier), do: nil

  @doc "{partial, missing} — which optional CRO fields are unspecified."
  def is_partial(cro) do
    missing = Enum.filter(@cro_optional_fields, fn f -> not Map.has_key?(cro, f) end)
    {missing != [], missing}
  end

  @doc "Rule 4: temporal admissibility with the fixed constants."
  def admissible(cro, elapsed_seconds) do
    case Map.get(cro, "temporal") do
      nil ->
        # No window imposes no constraint.
        true

      t ->
        unit = Map.fetch!(@unit_seconds, Map.fetch!(t, "unit"))
        lo = Map.fetch!(t, "dmin") * unit
        hi = Map.fetch!(t, "dmax") * unit
        lo <= elapsed_seconds and elapsed_seconds <= hi
    end
  end

  defp window_overlap(a, b) do
    ta = Map.get(a, "temporal")
    tb = Map.get(b, "temporal")

    if ta == nil or tb == nil do
      # Either absent counts as overlapping.
      true
    else
      ua = Map.fetch!(@unit_seconds, Map.fetch!(ta, "unit"))
      ub = Map.fetch!(@unit_seconds, Map.fetch!(tb, "unit"))
      lo_a = Map.fetch!(ta, "dmin") * ua
      hi_a = Map.fetch!(ta, "dmax") * ua
      lo_b = Map.fetch!(tb, "dmin") * ub
      hi_b = Map.fetch!(tb, "dmax") * ub
      lo_a <= hi_b and lo_b <= hi_a
    end
  end

  defp contexts_compatible(a, b) do
    ca = Map.get(a, "context")
    cb = Map.get(b, "context")

    if ca == nil or ca == [] or cb == nil or cb == [] do
      # Either absent (or empty) is compatible with anything.
      true
    else
      sa = MapSet.new(ca)
      sb = MapSet.new(cb)
      MapSet.subset?(sa, sb) or MapSet.subset?(sb, sa)
    end
  end

  defp set_equal(a, b), do: MapSet.new(a) == MapSet.new(b)

  @doc "Rule 6: the formal conflict test."
  def conflicts(a, b) do
    cond do
      not set_equal(Map.fetch!(a, "causes"), Map.fetch!(b, "causes")) -> false
      not set_equal(Map.fetch!(a, "effects"), Map.fetch!(b, "effects")) -> false
      not contexts_compatible(a, b) -> false
      not window_overlap(a, b) -> false
      true -> preventive_vs_positive(Map.get(a, "modality"), Map.get(b, "modality"))
    end
  end

  defp preventive_vs_positive(ma, mb) do
    (ma == "preventive" and mb in @positive_modalities) or
      (mb == "preventive" and ma in @positive_modalities)
  end

  @doc "Rule 3: {ok, reason} — is child a valid refinement of parent?"
  def refinement_valid(child, parent) do
    cond do
      Map.get(child, "refines") != Map.get(parent, "id") ->
        {false, "child does not name the parent in refines"}

      not set_equal(Map.fetch!(child, "causes"), Map.fetch!(parent, "causes")) or
          not set_equal(Map.fetch!(child, "effects"), Map.fetch!(parent, "effects")) ->
        {false, "a refinement must keep the parent's causes and effects"}

      true ->
        check_refined_fields(child, parent)
    end
  end

  defp check_refined_fields(child, parent) do
    result =
      Enum.reduce_while(@cro_optional_fields, 0, fn field, added ->
        cond do
          Map.has_key?(parent, field) ->
            if Map.get(child, field) == Map.fetch!(parent, field) do
              {:cont, added}
            else
              {:halt, :rival}
            end

          Map.has_key?(child, field) ->
            {:cont, added + 1}

          true ->
            {:cont, added}
        end
      end)

    case result do
      :rival ->
        {false,
         "a refinement may not change a field the parent specified; this is a rival claim"}

      0 ->
        {false, "a refinement must add at least one unspecified field"}

      _added ->
        {true, "valid refinement"}
    end
  end

  @doc """
  Rule 7: "consistent" | "inconsistent" | "indeterminate".

  `members` is a map from CRO identifier to CRO object for the parent's
  mechanism entries (the store's view of them).
  """
  def hierarchy_consistent(parent, members) do
    mechanism = Map.get(parent, "mechanism", [])

    if mechanism == [] do
      # Nothing claimed, nothing to check.
      "consistent"
    else
      case build_mechanism_edges(mechanism, members) do
        :indeterminate ->
          # A dangling_reference gap, not a failure.
          "indeterminate"

        edges ->
          all_reachable =
            Enum.all?(Map.fetch!(parent, "causes"), fn c ->
              Enum.all?(Map.fetch!(parent, "effects"), fn e -> reachable?(edges, c, e) end)
            end)

          if all_reachable, do: "consistent", else: "inconsistent"
      end
    end
  end

  defp build_mechanism_edges(mechanism, members) do
    Enum.reduce_while(mechanism, %{}, fn mid, edges ->
      case Map.get(members, mid) do
        nil ->
          {:halt, :indeterminate}

        m ->
          edges =
            Enum.reduce(Map.fetch!(m, "causes"), edges, fn c, acc ->
              Map.update(
                acc,
                c,
                MapSet.new(Map.fetch!(m, "effects")),
                &MapSet.union(&1, MapSet.new(Map.fetch!(m, "effects")))
              )
            end)

          {:cont, edges}
      end
    end)
  end

  defp reachable?(edges, src, dst), do: reachable?(edges, [src], dst, MapSet.new())

  defp reachable?(_edges, [], _dst, _seen), do: false

  defp reachable?(edges, [node | stack], dst, seen) do
    cond do
      node == dst -> true
      MapSet.member?(seen, node) -> reachable?(edges, stack, dst, seen)
      true ->
        next = edges |> Map.get(node, MapSet.new()) |> MapSet.to_list()
        reachable?(edges, next ++ stack, dst, MapSet.put(seen, node))
    end
  end
end
