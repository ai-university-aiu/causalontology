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

  # 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete step
  # with NO wall-clock mapping; a tick window is ordered by integer comparison,
  # and an ordinal window and a wall-clock window are DIFFERENT DIMENSIONS that
  # do not compare (mixing them is never within-window and never overlapping).
  @ordinal_units MapSet.new(["ticks"])

  # 'ordinal' for a tick-like unit, else 'wallclock'.
  defp dimension(unit), do: if(MapSet.member?(@ordinal_units, unit), do: "ordinal", else: "wallclock")

  # A comparable magnitude within ONE dimension: raw tick count for an ordinal
  # unit, seconds for a wall-clock unit. Never mix dimensions.
  defp magnitude(value, unit) do
    cond do
      MapSet.member?(@ordinal_units, unit) -> value
      unit == "instant" -> 0
      true -> value * Map.fetch!(@unit_seconds, unit)
    end
  end

  # Rule 12: enrichment field-to-kind validity and entry shapes. Two occurrent
  # forms added in 2.0.0.
  @enrichment_fields %{
    "aliases" => {["occurrent", "continuant"], "alias"},
    "participants" => {["occurrent"], "continuant"},
    "subsumes" => {["continuant"], "continuant"},
    "part_of" => {["continuant"], "continuant"},
    "realized_in" => {["realizable"], "occurrent"},
    "occurrent_subsumes" => {["occurrent"], "occurrent"},
    "occurrent_part_of" => {["occurrent"], "occurrent"}
  }

  @cro_optional_fields ["mechanism", "temporal", "modality", "context"]

  # Rule 6 (amended): necessary, sufficient, contributory, enabling are mutually
  # compatible; preventive opposes all four.
  @positive_modalities ["necessary", "sufficient", "contributory", "enabling"]

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
        "causal_relation_object" -> cro_errors(obj)
        "enrichment" -> enrichment_errors(obj)
        "cross_stratal_seam" -> seam_errors(obj)
        "predicted_occurrence" -> predicted_errors(obj)
        _ -> []
      end

    {errors == [], errors}
  end

  # 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain has, by
  # drawing it, a modelled intervening mechanism - so mechanism_status 'absent'
  # contradicts a present chain (the honest-ignorance distinction must stay
  # honest). The stratal well-formedness (non-adjacency, adjacency of chain
  # steps, scheme, the home rule) needs the strata map and lives in
  # seam_wellformed, exactly as bridge well-formedness does.
  defp seam_errors(obj) do
    if Map.get(obj, "chain") != nil and Map.get(obj, "mechanism_status") == "absent" do
      [
        "contradictory_seam: a drawn chain cannot carry mechanism_status " <>
          "'absent' (a drawn mechanism is not absent)"
      ]
    else
      []
    end
  end

  # 4.0.0 Rule 24, local clause: a predicted_occurrence's interval carries
  # exactly ONE temporal dimension - a wall-clock start (optional end) or an
  # ordinal start_tick (optional end_tick), never both and never neither. Per
  # Rule 23 the two dimensions never compare. The pairing check of a
  # prediction_error against its predicted_occurrence and its observed
  # token_occurrence needs those objects and lives in
  # prediction_pairing_mismatch, exactly as covering_law_mismatch does.
  defp predicted_errors(obj) do
    iv = Map.get(obj, "interval") || %{}
    wall = Map.has_key?(iv, "start")
    tick = Map.has_key?(iv, "start_tick")

    cond do
      wall and tick ->
        [
          "dimension_conflict: a predicted interval must carry exactly one " <>
            "temporal dimension, not a wall-clock start AND an ordinal start_tick"
        ]

      not wall and not tick ->
        [
          "missing_dimension: a predicted interval must carry a wall-clock " <>
            "start or an ordinal start_tick"
        ]

      true ->
        []
    end
  end

  defp cro_errors(obj) do
    temporal = Map.get(obj, "temporal")
    oid = Map.get(obj, "id")
    errors = []

    errors =
      if is_map(temporal) and Map.get(temporal, "minimum_delay") != nil and
           Map.get(temporal, "maximum_delay") != nil and
           Map.fetch!(temporal, "minimum_delay") > Map.fetch!(temporal, "maximum_delay") do
        errors ++ ["minimum_delay must be <= maximum_delay"]
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

    errors =
      if oid != nil and Map.get(obj, "refines") == oid do
        errors ++ ["refines must be acyclic"]
      else
        errors
      end

    # Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
    # contradiction between skips:true and a non-empty mechanism.
    if Map.get(obj, "skips") == true and truthy_mechanism(obj) do
      errors ++ ["contradictory_skip: skips is true but a mechanism is present"]
    else
      errors
    end
  end

  defp truthy_mechanism(obj) do
    case Map.get(obj, "mechanism") do
      nil -> false
      [] -> false
      _ -> true
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

  @doc """
  Rule 4: temporal admissibility. For a wall-clock window `elapsed` is in
  seconds; for an ordinal ('ticks') window `elapsed` is a tick count. Ordering
  is by magnitude WITHIN the window's own dimension (3.0.0).
  """
  def admissible(cro, elapsed) do
    case Map.get(cro, "temporal") do
      nil ->
        # No window imposes no constraint.
        true

      t ->
        unit = Map.fetch!(t, "unit")
        lo = magnitude(Map.fetch!(t, "minimum_delay"), unit)
        hi = magnitude(Map.fetch!(t, "maximum_delay"), unit)
        lo <= elapsed and elapsed <= hi
    end
  end

  defp window_overlap(a, b) do
    ta = Map.get(a, "temporal")
    tb = Map.get(b, "temporal")

    cond do
      ta == nil or tb == nil ->
        # Either absent counts as overlapping.
        true

      dimension(Map.fetch!(ta, "unit")) != dimension(Map.fetch!(tb, "unit")) ->
        # 3.0.0: an ordinal window and a wall-clock window never overlap.
        false

      true ->
        ua = Map.fetch!(ta, "unit")
        ub = Map.fetch!(tb, "unit")
        lo_a = magnitude(Map.fetch!(ta, "minimum_delay"), ua)
        hi_a = magnitude(Map.fetch!(ta, "maximum_delay"), ua)
        lo_b = magnitude(Map.fetch!(tb, "minimum_delay"), ub)
        hi_b = magnitude(Map.fetch!(tb, "maximum_delay"), ub)
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

  # ===========================================================================
  # 2.0.0 NORMATIVE ALGORITHMS (Section 12)
  # ===========================================================================

  @doc """
  ALGORITHM A. Every finer occurrent an occurrent resolves to, following
  Bridges downward, transitively. Includes the starting occurrent (N12.1.1).
  `bridges` is any list of bridge objects. A visited guard (N12.1.2) prevents
  an infinite loop on malformed cyclic data. Returns a MapSet.
  """
  def bridge_closure(occurrent_id, bridges) do
    coarse_index =
      Enum.reduce(bridges, %{}, fn b, acc ->
        Map.update(acc, Map.fetch!(b, "coarse"), [b], &(&1 ++ [b]))
      end)

    close([occurrent_id], MapSet.new([occurrent_id]), MapSet.new(), coarse_index)
  end

  defp close([], result, _visited, _index), do: result

  defp close([current | frontier], result, visited, index) do
    if MapSet.member?(visited, current) do
      close(frontier, result, visited, index)
    else
      visited = MapSet.put(visited, current)

      {result, frontier} =
        Enum.reduce(Map.get(index, current, []), {result, frontier}, fn b, {res, fr} ->
          Enum.reduce(Map.fetch!(b, "fine"), {res, fr}, fn f, {res, fr} ->
            {MapSet.put(res, f), [f | fr]}
          end)
        end)

      close(frontier, result, visited, index)
    end
  end

  @doc """
  ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" | "indeterminate",
  ACROSS STRATA via bridged reachability.

  `members` is a map from CRO identifier to CRO object for the parent's
  mechanism entries. `bridges` is the store's bridges (empty -> 1.0.0 literal
  reachability, the degenerate case, N12.2.3).
  """
  def hierarchy_consistent(parent, members, bridges \\ []) do
    mechanism = Map.get(parent, "mechanism", [])

    if mechanism == [] do
      # Nothing claimed, nothing to check (N12.2.1).
      "consistent"
    else
      case build_mechanism_edges(mechanism, members) do
        :indeterminate ->
          # Dangling; ignorance, not refutation.
          "indeterminate"

        edges ->
          causes = Map.fetch!(parent, "causes")
          effects = Map.fetch!(parent, "effects")
          b_cause = Map.new(causes, fn c -> {c, bridge_closure(c, bridges)} end)
          b_effect = Map.new(effects, fn e -> {e, bridge_closure(e, bridges)} end)

          connected? =
            Enum.all?(causes, fn c ->
              Enum.all?(effects, fn e ->
                Enum.any?(Map.fetch!(b_cause, c), fn cp ->
                  Enum.any?(Map.fetch!(b_effect, e), fn ep -> reachable?(edges, cp, ep) end)
                end)
              end)
            end)

          if connected?, do: "consistent", else: "inconsistent"
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
      node == dst ->
        true

      MapSet.member?(seen, node) ->
        reachable?(edges, stack, dst, seen)

      true ->
        next = edges |> Map.get(node, MapSet.new()) |> MapSet.to_list()
        reachable?(edges, next ++ stack, dst, MapSet.put(seen, node))
    end
  end

  @doc """
  ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping" |
  "mixed" | "unclassifiable" | "scheme_mismatch". Derived, never asserted.
  """
  def classify_cro(cro, occ_map, stratum_map) do
    cause_strata = Enum.map(Map.fetch!(cro, "causes"), &stratum_of(occ_map, &1))
    effect_strata = Enum.map(Map.fetch!(cro, "effects"), &stratum_of(occ_map, &1))

    cond do
      Enum.any?(cause_strata ++ effect_strata, &is_nil/1) ->
        "unclassifiable"

      true ->
        all_strata = MapSet.new(cause_strata ++ effect_strata)
        schemes = MapSet.new(all_strata, fn s -> Map.fetch!(Map.fetch!(stratum_map, s), "scheme") end)

        if MapSet.size(schemes) > 1 do
          "scheme_mismatch"
        else
          c_ord = Enum.map(cause_strata, &ordinal(stratum_map, &1))
          e_ord = Enum.map(effect_strata, &ordinal(stratum_map, &1))

          cond do
            Enum.max(c_ord) == Enum.min(c_ord) and Enum.min(c_ord) == Enum.max(e_ord) and
                Enum.max(e_ord) == Enum.min(e_ord) ->
              "intra_stratal"

            true ->
              pairs = for i <- c_ord, j <- e_ord, do: abs(i - j)
              gap = Enum.min(pairs)
              span = Enum.max(pairs)

              cond do
                span == 1 -> "adjacent_stratal"
                gap > 1 -> "skipping"
                true -> "mixed"
              end
          end
        end
    end
  end

  defp stratum_of(occ_map, occ_id), do: occ_map |> Map.get(occ_id, %{}) |> Map.get("stratum")

  defp ordinal(stratum_map, s), do: Map.fetch!(Map.fetch!(stratum_map, s), "ordinal")

  @doc """
  True iff causes or effects span more than one distinct stratum (surfaces
  mixed_stratal_endpoints, an invitation; N12.3.2).
  """
  def endpoints_mixed(cro, occ_map) do
    cs = MapSet.new(Map.fetch!(cro, "causes"), &stratum_of(occ_map, &1))
    es = MapSet.new(Map.fetch!(cro, "effects"), &stratum_of(occ_map, &1))

    if MapSet.member?(cs, nil) or MapSet.member?(es, nil) do
      false
    else
      MapSet.size(cs) > 1 or MapSet.size(es) > 1
    end
  end

  @doc """
  ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
  skip decision. THE ASYMMETRY (clause 3) is implemented exactly.
  """
  def skip_gaps(cro, classification) do
    has_mech = truthy_mechanism(cro)
    skips_true = Map.get(cro, "skips") == true

    cond do
      skips_true and has_mech ->
        ["contradictory_skip"]

      true ->
        gaps =
          if skips_true and classification not in ["skipping", "unclassifiable"] do
            ["vacuous_skip"]
          else
            []
          end

        if classification == "skipping" and not has_mech do
          if skips_true do
            # NOTHING: absence is a finding.
            gaps
          else
            gaps ++ ["incomplete_mechanism"]
          end
        else
          gaps
        end
    end
  end

  @doc """
  ALGORITHM E helper: normalize a delay to seconds by the fixed table. 3.0.0:
  an ordinal ('ticks') unit is dimensionless and has NO wall-clock mapping -
  converting one to seconds is a category error and is refused.
  """
  def to_seconds(_duration, "instant"), do: 0

  def to_seconds(duration, unit) do
    if MapSet.member?(@ordinal_units, unit) do
      raise ArgumentError,
            "'#{unit}' is an ordinal (dimensionless) unit and has no " <>
              "wall-clock seconds mapping"
    end

    duration * Map.fetch!(@unit_seconds, unit)
  end

  @doc """
  ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
  temporal window? Inclusive at both ends (N12.5.2). 3.0.0: an ordinal delay
  compares to an ordinal window by integer tick count; an ordinal delay and a
  wall-clock window (or vice versa) are different dimensions and never fall
  within one another.
  """
  def delay_within_window(actual_delay, temporal) do
    cond do
      is_nil(actual_delay) or actual_delay == %{} or is_nil(temporal) or temporal == %{} ->
        # Nothing to check.
        true

      dimension(Map.fetch!(actual_delay, "unit")) != dimension(Map.fetch!(temporal, "unit")) ->
        # Dimension mismatch: a tick delay is not within a wall-clock window.
        false

      true ->
        du = Map.fetch!(actual_delay, "unit")
        tu = Map.fetch!(temporal, "unit")
        observed = magnitude(Map.fetch!(actual_delay, "duration"), du)
        lo = magnitude(Map.fetch!(temporal, "minimum_delay"), tu)
        hi = magnitude(Map.fetch!(temporal, "maximum_delay"), tu)
        lo <= observed and observed <= hi
    end
  end

  @doc """
  Rule 14 / N3.2.1: Bridge well-formedness. All of (a)-(e) must hold, else
  malformed_bridge. Returns {ok, reason}.
  """
  def bridge_wellformed(bridge, occ_map, stratum_map) do
    coarse = Map.get(occ_map, Map.fetch!(bridge, "coarse"), %{})
    cs = Map.get(coarse, "stratum")
    fine_strata = Enum.map(Map.fetch!(bridge, "fine"), fn f -> Map.get(occ_map, f, %{})["stratum"] end)

    cond do
      is_nil(cs) ->
        {false, "malformed_bridge: coarse has no stratum (a)"}

      Enum.any?(fine_strata, &is_nil/1) ->
        {false, "malformed_bridge: a fine member has no stratum (b)"}

      MapSet.size(MapSet.new(fine_strata)) != 1 ->
        {false, "malformed_bridge: fine members span >1 stratum (c)"}

      true ->
        fs = hd(fine_strata)

        cond do
          Map.fetch!(Map.fetch!(stratum_map, cs), "scheme") !=
              Map.fetch!(Map.fetch!(stratum_map, fs), "scheme") ->
            {false, "malformed_bridge: coarse and fine differ in scheme (d)"}

          not (ordinal(stratum_map, cs) > ordinal(stratum_map, fs)) ->
            {false, "malformed_bridge: coarse ordinal not > fine ordinal (e)"}

          true ->
            {true, "well-formed bridge"}
        end
    end
  end

  @doc """
  3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness. All of
  (a)-(g) must hold, else malformed_seam. Returns {ok, reason}. A seam is a
  MANAGED jump across NON-ADJACENT strata; when it DRAWS a chain, the chain must
  be an adjacent-stratum path spanning the two endpoints' strata.
  """
  def seam_wellformed(seam, occ_map, stratum_map) do
    src_s = stratum_of(occ_map, Map.fetch!(seam, "source"))
    tgt_s = stratum_of(occ_map, Map.fetch!(seam, "target"))

    cond do
      is_nil(src_s) or is_nil(tgt_s) ->
        {false, "malformed_seam: an endpoint has no stratum (a)"}

      Map.fetch!(Map.fetch!(stratum_map, src_s), "scheme") !=
          Map.fetch!(Map.fetch!(stratum_map, tgt_s), "scheme") ->
        {false, "malformed_seam: endpoints differ in scheme (b)"}

      abs(ordinal(stratum_map, src_s) - ordinal(stratum_map, tgt_s)) <= 1 ->
        {false,
         "malformed_seam: endpoints are adjacent or co-stratal; " <>
           "a seam is for NON-adjacent strata (c)"}

      Map.get(seam, "chain") == nil ->
        {true, "well-formed cross_stratal_seam"}

      true ->
        seam_chain_wellformed(seam, occ_map, stratum_map, src_s)
    end
  end

  defp seam_chain_wellformed(seam, occ_map, stratum_map, src_s) do
    so = ordinal(stratum_map, src_s)
    to_ = ordinal(stratum_map, stratum_of(occ_map, Map.fetch!(seam, "target")))
    lo = min(so, to_)
    hi = max(so, to_)
    scheme = Map.fetch!(Map.fetch!(stratum_map, src_s), "scheme")

    if Map.get(seam, "mechanism_status") == "absent" do
      {false, "malformed_seam: a drawn chain contradicts mechanism_status 'absent' (d)"}
    else
      collected =
        Enum.reduce_while(Map.fetch!(seam, "chain"), {:ok, []}, fn oid, {:ok, acc} ->
          st = stratum_of(occ_map, oid)

          cond do
            is_nil(st) ->
              {:halt, {:error, "malformed_seam: a chain member has no stratum (e)"}}

            Map.fetch!(Map.fetch!(stratum_map, st), "scheme") != scheme ->
              {:halt, {:error, "malformed_seam: a chain member differs in scheme (e)"}}

            true ->
              {:cont, {:ok, acc ++ [ordinal(stratum_map, st)]}}
          end
        end)

      case collected do
        {:error, msg} ->
          {false, msg}

        {:ok, ords} ->
          cond do
            not Enum.all?(ords, fn o -> lo < o and o < hi end) ->
              {false,
               "malformed_seam: a chain member is not at an INTERVENING " <>
                 "stratum, strictly between the endpoints (f)"}

            not monotone?(ords) ->
              {false,
               "malformed_seam: chain is not strictly monotone from " <>
                 "one endpoint toward the other (g)"}

            true ->
              {true, "well-formed cross_stratal_seam"}
          end
      end
    end
  end

  # Strictly monotone (all steps positive, or all steps negative); one or zero
  # elements are vacuously monotone.
  defp monotone?(ords) when length(ords) <= 1, do: true

  defp monotone?(ords) do
    diffs = ords |> Enum.zip(tl(ords)) |> Enum.map(fn {a, b} -> b - a end)
    Enum.all?(diffs, &(&1 > 0)) or Enum.all?(diffs, &(&1 < 0))
  end

  @doc """
  THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST stratum it
  touches - the endpoint of the greater ordinal. Returns that stratum's
  identifier (nil if an endpoint is unstratified).
  """
  def seam_home(seam, occ_map, stratum_map) do
    src_s = stratum_of(occ_map, Map.fetch!(seam, "source"))
    tgt_s = stratum_of(occ_map, Map.fetch!(seam, "target"))

    cond do
      is_nil(src_s) or is_nil(tgt_s) -> nil
      ordinal(stratum_map, src_s) >= ordinal(stratum_map, tgt_s) -> src_s
      true -> tgt_s
    end
  end

  @doc """
  Rule 17 / N4.2.1-2: Conduit well-formedness. N4.2.1 with the transform
  exception of N4.2.2. Returns {ok, reason}.
  """
  def conduit_wellformed(conduit, port_map, cro_map \\ %{}) do
    frm = Map.get(port_map, Map.fetch!(conduit, "from"))
    to = Map.get(port_map, Map.fetch!(conduit, "to"))

    cond do
      is_nil(frm) or is_nil(to) ->
        {false, "malformed_conduit: dangling port reference"}

      Map.fetch!(frm, "direction") not in ["out", "bidirectional"] ->
        {false, "malformed_conduit: from port is not out/bidirectional (a)"}

      Map.fetch!(to, "direction") not in ["in", "bidirectional"] ->
        {false, "malformed_conduit: to port is not in/bidirectional (b)"}

      not Enum.all?(Map.fetch!(conduit, "carries"), &(&1 in Map.fetch!(frm, "accepts"))) ->
        {false, "malformed_conduit: carries not accepted by from (c)"}

      true ->
        conduit_to_check(conduit, to, cro_map)
    end
  end

  defp conduit_to_check(conduit, to, cro_map) do
    case Map.get(conduit, "transform") do
      nil ->
        if Enum.all?(Map.fetch!(conduit, "carries"), &(&1 in Map.fetch!(to, "accepts"))) do
          {true, "well-formed conduit"}
        else
          {false, "malformed_conduit: carries not accepted by to (d)"}
        end

      transform ->
        case Map.get(cro_map, transform) do
          nil ->
            {true, "well-formed conduit"}

          law ->
            if Enum.all?(Map.fetch!(law, "effects"), &(&1 in Map.fetch!(to, "accepts"))) do
              {true, "well-formed conduit"}
            else
              {false, "malformed_conduit: transform effects not accepted by to (d, relaxed per N4.2.2)"}
            end
        end
    end
  end

  @doc """
  Rule 19 / N5.3.1-2: State value type and unit coherence. The HARD gaps a
  state assertion surfaces against its quality: value_type_mismatch and/or
  unit_mismatch.
  """
  def state_gaps(state, quality) do
    dt = Map.get(quality, "datatype")
    v = Map.get(state, "value", %{})

    shape =
      cond do
        Map.has_key?(v, "quantity") -> "quantity"
        Map.has_key?(v, "categorical") -> "categorical"
        Map.has_key?(v, "boolean") -> "boolean"
        true -> nil
      end

    cond do
      shape != dt -> ["value_type_mismatch"]
      dt == "quantity" and Map.get(v, "unit") != Map.get(quality, "unit") -> ["unit_mismatch"]
      true -> []
    end
  end

  @doc """
  Rule 20: True iff the token claim's cause/effect tokens do not instantiate
  the covering law's causes/effects (surfaces covering_law_mismatch).
  """
  def covering_law_mismatch(tcc, token_map, law) do
    if is_nil(law) or law == %{} do
      false
    else
      law_causes = MapSet.new(Map.fetch!(law, "causes"))
      law_effects = MapSet.new(Map.fetch!(law, "effects"))

      cause_bad =
        Enum.any?(Map.fetch!(tcc, "causes"), fn c ->
          not MapSet.member?(law_causes, Map.fetch!(Map.fetch!(token_map, c), "instantiates"))
        end)

      effect_bad =
        Enum.any?(Map.fetch!(tcc, "effects"), fn e ->
          not MapSet.member?(law_effects, Map.fetch!(Map.fetch!(token_map, e), "instantiates"))
        end)

      cause_bad or effect_bad
    end
  end

  @doc """
  4.0.0 Rule 24: prediction-to-observation pairing. True iff the prediction
  error's observed token does not instantiate the occurrent its
  predicted_occurrence instantiates (surfaces pairing_mismatch). An ABSENT
  observed is never a mismatch - it means the predicted occurrence was not
  fulfilled by any recorded occurrence.
  """
  def prediction_pairing_mismatch(error, predicted, observed) do
    if Map.get(error, "observed") == nil or observed == nil do
      false
    else
      Map.fetch!(observed, "instantiates") != Map.fetch!(predicted, "instantiates")
    end
  end

  @doc """
  Rule 21: True iff any cause token starts after any effect token (HARD;
  retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically.
  """
  def retrocausal(tcc, token_map) do
    Enum.any?(Map.fetch!(tcc, "causes"), fn c ->
      cstart = Map.fetch!(token_map, c) |> Map.fetch!("interval") |> Map.fetch!("start")

      Enum.any?(Map.fetch!(tcc, "effects"), fn e ->
        estart = Map.fetch!(token_map, e) |> Map.fetch!("interval") |> Map.fetch!("start")
        cstart > estart
      end)
    end)
  end

  @doc """
  Rules 4 / 6.1: generic acyclicity for the new graph relations. True iff a
  directed graph (map node -> list of successors) has a cycle. Used for the
  bridge graph, occurrent_subsumes, occurrent_part_of, and token mereology.
  """
  def has_cycle(edges) do
    Enum.reduce_while(Map.keys(edges), %{}, fn node, state ->
      if Map.get(state, node, :white) == :white do
        case cycle_visit(node, edges, state) do
          {true, _state} -> {:halt, :cycle}
          {false, state} -> {:cont, state}
        end
      else
        {:cont, state}
      end
    end) == :cycle
  end

  defp cycle_visit(node, edges, state) do
    state = Map.put(state, node, :grey)

    result =
      Enum.reduce_while(Map.get(edges, node, []), {false, state}, fn nxt, {false, state} ->
        case Map.get(state, nxt, :white) do
          :grey ->
            {:halt, {true, state}}

          :white ->
            case cycle_visit(nxt, edges, state) do
              {true, state} -> {:halt, {true, state}}
              {false, state} -> {:cont, {false, state}}
            end

          :black ->
            {:cont, {false, state}}
        end
      end)

    case result do
      {true, state} -> {true, state}
      {false, state} -> {false, Map.put(state, node, :black)}
    end
  end
end
