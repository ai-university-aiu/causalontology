defmodule Causalontology.Store do
  @moduledoc """
  An in-memory conformant store.

  Implements the store side of the abstract operation set (spec/store.md):
  immutable content objects with idempotent put; signed, add-only provenance
  records; materialized enrichment views with contributors; retraction handling
  in default views; succession lineage; the resolve minimum; the deterministic
  cycle-breaking view rule; and the stigmergy gap read.

  The store is immutable-functional: every write returns
  `{:ok, store, id}` or `{:error, store, reason}` (a rejected write returns
  the store unchanged, except a quarantined record, which is captured in the
  returned store's quarantine before the error is reported — mirroring the
  Python reference, which mutates the quarantine and then raises).

  Elixir maps are unordered, so explicit insertion-order id lists ride
  alongside the object and record maps; everything the Python reference
  iterates in dict insertion order is iterated here in the same order.
  """

  alias Causalontology.{Canonical, Schema, Semantics, Signing}

  @content_kinds ["occurrent", "causal_relation_object", "continuant", "realizable"]
  @record_kinds ["assertion", "enrichment", "retraction", "succession"]

  defstruct enforcing: true,
            objects: %{},
            object_order: [],
            records: %{},
            record_order: [],
            quarantine: %{},
            quarantine_order: []

  @doc "A fresh store; `enforcing: false` models a non-enforcing tier."
  def new(enforcing \\ true), do: %__MODULE__{enforcing: enforcing}

  # -------------------------------------------------------------------- put

  @doc "Write a content object; idempotent; returns {:ok, store, id}."
  def put(%__MODULE__{} = store, obj, kind \\ nil) do
    kind = kind || Canonical.infer_kind(obj)

    if kind not in @content_kinds do
      raise ArgumentError, "put/3 takes content objects; use put_record/4"
    end

    obj = Map.put_new(obj, "type", kind)

    obj =
      if Map.has_key?(obj, "id") do
        obj
      else
        Map.put(obj, "id", Canonical.identify(obj, kind))
      end

    id = Map.fetch!(obj, "id")

    if Map.has_key?(store.objects, id) do
      # Immutable: identical identity is a no-op.
      {:ok, store, id}
    else
      with {_, {true, _}} <- {:schema, Schema.validate_schema(obj, kind)},
           {_, {true, _}} <- {:semantics, Semantics.validate_semantics(obj, kind)} do
        store = %{
          store
          | objects: Map.put(store.objects, id, obj),
            object_order: store.object_order ++ [id]
        }

        {:ok, store, id}
      else
        {_stage, {false, why}} -> {:error, store, Enum.join(why, "; ")}
      end
    end
  end

  @doc "Write a signed provenance record; returns {:ok, store, id}."
  def put_record(%__MODULE__{} = store, record, kind \\ nil, force \\ false) do
    kind = kind || Canonical.infer_kind(record)

    if kind not in @record_kinds do
      raise ArgumentError, "put_record/4 takes provenance records"
    end

    record = Map.put_new(record, "type", kind)
    rid = Map.get(record, "id") || Canonical.identify(record, kind)
    record = Map.put(record, "id", rid)

    cond do
      Map.has_key?(store.records, rid) ->
        # Add-only and idempotent.
        {:ok, store, rid}

      not Signing.verify_record(record, kind) ->
        {:error, quarantine(store, rid, record),
         "unsigned or unverifiable record: quarantined"}

      true ->
        case Semantics.validate_semantics(record, kind) do
          {false, why} ->
            {:error, store, Enum.join(why, "; ")}

          {true, _} ->
            put_record_gated(store, record, kind, rid, force)
        end
    end
  end

  defp put_record_gated(store, record, kind, rid, force) do
    cond do
      kind == "retraction" and not retraction_source_ok(store, record) ->
        {:error, store,
         "a retraction is valid only from the retracted record's " <>
           "source or its succession lineage"}

      kind == "enrichment" and store.enforcing and not force and
        Map.fetch!(record, "field") in ["subsumes", "part_of"] and
          would_cycle(store, record) ->
        {:error, store,
         "would create a cycle in the materialized #{Map.fetch!(record, "field")} graph"}

      true ->
        store = %{
          store
          | records: Map.put(store.records, rid, record),
            record_order: store.record_order ++ [rid]
        }

        {:ok, store, rid}
    end
  end

  @doc "Simulate a decentralized replica merge (no enforcement gate)."
  def force_merge_record(store, record, kind \\ nil),
    do: put_record(store, record, kind, true)

  defp quarantine(store, rid, record) do
    if Map.has_key?(store.quarantine, rid) do
      store
    else
      %{
        store
        | quarantine: Map.put(store.quarantine, rid, record),
          quarantine_order: store.quarantine_order ++ [rid]
      }
    end
  end

  # --------------------------------------------------------- record queries

  # All records of one kind, in insertion order.
  defp records_of(store, kind) do
    store.record_order
    |> Enum.map(&Map.fetch!(store.records, &1))
    |> Enum.filter(&(Map.get(&1, "type") == kind))
  end

  defp retracted_ids(store) do
    store |> records_of("retraction") |> MapSet.new(&Map.fetch!(&1, "retracts"))
  end

  defp retraction_source_ok(store, retraction) do
    case Map.get(store.records, Map.fetch!(retraction, "retracts")) do
      nil ->
        # Open world: the target may arrive later.
        true

      target ->
        MapSet.member?(
          lineage(store, Map.fetch!(target, "source")),
          Map.fetch!(retraction, "source")
        )
    end
  end

  @doc "The succession chain closure containing key (includes key), as a MapSet."
  def lineage(%__MODULE__{} = store, key) do
    {succ, pred} =
      Enum.reduce(records_of(store, "succession"), {%{}, %{}}, fn s, {succ, pred} ->
        {Map.put(succ, Map.fetch!(s, "predecessor"), Map.fetch!(s, "successor")),
         Map.put(pred, Map.fetch!(s, "successor"), Map.fetch!(s, "predecessor"))}
      end)

    MapSet.new([key])
    |> walk_chain(key, pred)
    |> walk_chain(key, succ)
  end

  defp walk_chain(chain, cursor, links) do
    case Map.get(links, cursor) do
      nil ->
        chain

      next ->
        # The visited check terminates even on a (malformed) succession cycle.
        if MapSet.member?(chain, next) do
          chain
        else
          walk_chain(MapSet.put(chain, next), next, links)
        end
    end
  end

  @doc "Non-retracted assertions about an identifier (history flags retracted ones)."
  def assertions_about(%__MODULE__{} = store, identifier, include_retracted \\ false) do
    retracted = retracted_ids(store)

    Enum.reduce(records_of(store, "assertion"), [], fn r, out ->
      cond do
        Map.fetch!(r, "about") != identifier ->
          out

        MapSet.member?(retracted, Map.fetch!(r, "id")) ->
          if include_retracted, do: out ++ [Map.put(r, "retracted", true)], else: out

        true ->
          out ++ [r]
      end
    end)
  end

  @doc "Non-retracted enrichments about an identifier (history includes retracted)."
  def enrichments_about(%__MODULE__{} = store, identifier, include_retracted \\ false) do
    retracted = retracted_ids(store)

    Enum.filter(records_of(store, "enrichment"), fn r ->
      Map.fetch!(r, "about") == identifier and
        (include_retracted or not MapSet.member?(retracted, Map.fetch!(r, "id")))
    end)
  end

  # ---------------------------------------------------- materialized views

  @doc "{active, excluded} for subsumes/part_of after rule 13 cycle-breaking."
  def active_taxonomy_edges(%__MODULE__{} = store, field) do
    retracted = retracted_ids(store)

    recs =
      store
      |> records_of("enrichment")
      |> Enum.filter(fn r ->
        Map.fetch!(r, "field") == field and
          not MapSet.member?(retracted, Map.fetch!(r, "id"))
      end)

    break_cycles(recs, [])
  end

  defp break_cycles(active, excluded) do
    case find_cycle_records(active) do
      [] ->
        {active, excluded}

      cycle ->
        # Exclude the cycle-completing record with the LATEST timestamp,
        # ties broken by lexicographic record identifier (deterministic).
        loser =
          Enum.max_by(cycle, fn r -> {Map.fetch!(r, "timestamp"), Map.fetch!(r, "id")} end)

        active = Enum.reject(active, &(Map.fetch!(&1, "id") == Map.fetch!(loser, "id")))
        break_cycles(active, excluded ++ [loser])
    end
  end

  # Depth-first search over the about -> entry edges, in record insertion
  # order; returns the records along the first cycle found, or [].
  defp find_cycle_records(recs) do
    {edges, node_order} =
      Enum.reduce(recs, {%{}, []}, fn rec, {edges, order} ->
        about = Map.fetch!(rec, "about")
        edge = {Map.fetch!(rec, "entry"), rec}

        if Map.has_key?(edges, about) do
          {Map.update!(edges, about, &(&1 ++ [edge])), order}
        else
          {Map.put(edges, about, [edge]), order ++ [about]}
        end
      end)

    result =
      Enum.reduce_while(node_order, %{}, fn start, state ->
        if Map.get(state, start, 0) == 0 do
          case dfs(start, [], edges, state) do
            {nil, state} -> {:cont, state}
            {cycle, _state} -> {:halt, {:cycle, cycle}}
          end
        else
          {:cont, state}
        end
      end)

    case result do
      {:cycle, cycle} -> cycle
      _state -> []
    end
  end

  defp dfs(node, path_records, edges, state) do
    state = Map.put(state, node, 1)

    result =
      Enum.reduce_while(Map.get(edges, node, []), {nil, state}, fn {nxt, rec}, {nil, state} ->
        case Map.get(state, nxt, 0) do
          1 ->
            {:halt, {path_records ++ [rec], state}}

          0 ->
            case dfs(nxt, path_records ++ [rec], edges, state) do
              {nil, state} -> {:cont, {nil, state}}
              {cycle, state} -> {:halt, {cycle, state}}
            end

          _done ->
            {:cont, {nil, state}}
        end
      end)

    case result do
      {nil, state} -> {nil, Map.put(state, node, 2)}
      {cycle, state} -> {cycle, state}
    end
  end

  defp would_cycle(store, record) do
    retracted = retracted_ids(store)

    recs =
      store
      |> records_of("enrichment")
      |> Enum.filter(fn r ->
        Map.fetch!(r, "field") == Map.fetch!(record, "field") and
          not MapSet.member?(retracted, Map.fetch!(r, "id"))
      end)

    find_cycle_records(recs ++ [record]) != []
  end

  @doc "The object with its materialized enrichment sets and contributors."
  def get(%__MODULE__{} = store, identifier, view \\ "default") do
    case Map.get(store.objects, identifier) do
      nil ->
        nil

      obj ->
        if view == "raw" do
          %{"object" => obj}
        else
          %{"object" => obj, "enrichments" => materialize(store, identifier, view)}
        end
    end
  end

  defp materialize(store, identifier, view) do
    include_retracted = view == "history"

    excluded_ids =
      Enum.reduce(["subsumes", "part_of"], MapSet.new(), fn field, acc ->
        {_active, excluded} = active_taxonomy_edges(store, field)
        Enum.reduce(excluded, acc, fn r, a -> MapSet.put(a, Map.fetch!(r, "id")) end)
      end)

    {fields, field_order} =
      store
      |> enrichments_about(identifier, include_retracted)
      |> Enum.reduce({%{}, []}, fn rec, {fields, field_order} = acc ->
        if MapSet.member?(excluded_ids, Map.fetch!(rec, "id")) and view != "history" do
          acc
        else
          add_to_bucket(fields, field_order, rec)
        end
      end)

    Map.new(field_order, fn field ->
      {slot, entry_order} = Map.fetch!(fields, field)
      {field, Enum.map(entry_order, &Map.fetch!(slot, &1))}
    end)
  end

  defp add_to_bucket(fields, field_order, rec) do
    field = Map.fetch!(rec, "field")
    entry = Map.fetch!(rec, "entry")
    # The canonical-entry dedup key: a map entry keys by its sorted pairs.
    entry_key = if is_map(entry), do: Enum.sort(Map.to_list(entry)), else: entry
    contributor = %{"source" => Map.fetch!(rec, "source"), "timestamp" => Map.fetch!(rec, "timestamp")}

    {slot, entry_order, field_order} =
      case Map.get(fields, field) do
        nil -> {%{}, [], field_order ++ [field]}
        {slot, entry_order} -> {slot, entry_order, field_order}
      end

    {slot, entry_order} =
      case Map.get(slot, entry_key) do
        nil ->
          {Map.put(slot, entry_key, %{"entry" => entry, "contributors" => [contributor]}),
           entry_order ++ [entry_key]}

        bucket ->
          bucket = Map.update!(bucket, "contributors", &(&1 ++ [contributor]))
          {Map.put(slot, entry_key, bucket), entry_order}
      end

    {Map.put(fields, field, {slot, entry_order}), field_order}
  end

  # ------------------------------------------------------------------ resolve

  defp canon_label(text) do
    text |> String.trim() |> String.downcase() |> String.split() |> Enum.join("_")
  end

  defp norm_alias(text) do
    text |> String.split() |> Enum.join(" ") |> String.downcase()
  end

  @doc "The conformance minimum: exact label, then alias, then nothing."
  def resolve(%__MODULE__{} = store, text, lang \\ nil) do
    wanted_label = canon_label(text)
    wanted_alias = norm_alias(text)
    retracted = retracted_ids(store)
    enrichment_records = records_of(store, "enrichment")

    {label_hits, alias_hits} =
      Enum.reduce(store.object_order, {[], []}, fn oid, {labels, aliases} = acc ->
        obj = Map.fetch!(store.objects, oid)

        cond do
          Map.get(obj, "type") not in ["occurrent", "continuant"] ->
            acc

          Map.get(obj, "label") == wanted_label ->
            {labels ++ [oid], aliases}

          alias_match?(enrichment_records, oid, retracted, lang, wanted_alias) ->
            {labels, aliases ++ [oid]}

          true ->
            acc
        end
      end)

    label_hits ++ alias_hits
  end

  defp alias_match?(enrichment_records, oid, retracted, lang, wanted_alias) do
    Enum.any?(enrichment_records, fn rec ->
      entry = Map.fetch!(rec, "entry")

      Map.fetch!(rec, "about") == oid and
        Map.fetch!(rec, "field") == "aliases" and
        not MapSet.member?(retracted, Map.fetch!(rec, "id")) and
        is_map(entry) and
        (lang == nil or Map.get(entry, "lang") == lang) and
        norm_alias(Map.get(entry, "text", "")) == wanted_alias
    end)
  end

  # --------------------------------------------------------------------- gaps

  @doc "The stigmergy read. Gap kinds per spec/store.md; nil kind = all kinds."
  def gaps(%__MODULE__{} = store, kind \\ nil) do
    objects_in_order = Enum.map(store.object_order, &Map.fetch!(store.objects, &1))
    refined = refined_parents(store, objects_in_order)

    out =
      []
      |> field_gaps(objects_in_order, refined)
      |> hierarchy_gaps(store)
      |> dangling_gaps(store, objects_in_order)
      |> conflict_gaps(objects_in_order)

    if kind == nil, do: out, else: Enum.filter(out, &(Map.fetch!(&1, "kind") == kind))
  end

  # Parents closed by a valid refinement leave the gap lists.
  defp refined_parents(store, objects_in_order) do
    Enum.reduce(objects_in_order, MapSet.new(), fn obj, acc ->
      refines = Map.get(obj, "refines")

      with true <- Map.get(obj, "type") == "causal_relation_object",
           true <- is_binary(refines) and refines != "",
           parent when parent != nil <- Map.get(store.objects, refines),
           {true, _} <- Semantics.refinement_valid(obj, parent) do
        MapSet.put(acc, Map.fetch!(parent, "id"))
      else
        _ -> acc
      end
    end)
  end

  defp field_gaps(out, objects_in_order, refined) do
    Enum.reduce(objects_in_order, out, fn obj, out ->
      if Map.get(obj, "type") != "causal_relation_object" do
        out
      else
        oid = Map.fetch!(obj, "id")

        # missing_field: lacking the temporal window or the modality -
        # mechanism and context may legitimately stay unspecified forever
        # (empty_mechanism is its own kind; absent context = context-free).
        out =
          if (not Map.has_key?(obj, "temporal") or not Map.has_key?(obj, "modality")) and
               not MapSet.member?(refined, oid) do
            {_partial, missing} = Semantics.is_partial(obj)
            out ++ [%{"id" => oid, "kind" => "missing_field", "missing" => missing}]
          else
            out
          end

        if (not Map.has_key?(obj, "mechanism") or Map.get(obj, "mechanism") == []) and
             not MapSet.member?(refined, oid) do
          out ++ [%{"id" => oid, "kind" => "empty_mechanism"}]
        else
          out
        end
      end
    end)
  end

  defp hierarchy_gaps(out, store) do
    Enum.reduce(["subsumes", "part_of"], out, fn field, out ->
      {_active, excluded} = active_taxonomy_edges(store, field)

      out ++
        Enum.map(excluded, fn rec ->
          %{
            "id" => Map.fetch!(rec, "id"),
            "kind" => "inconsistent_hierarchy",
            "note" => "excluded by the deterministic cycle-breaking view rule"
          }
        end)
    end)
  end

  # dangling_reference: a reference to an object absent from the store -
  # the red link that says "this page is wanted".
  defp dangling_gaps(out, store, objects_in_order) do
    Enum.reduce(objects_in_order, out, fn obj, out ->
      refs =
        case Map.get(obj, "type") do
          "causal_relation_object" ->
            base =
              Map.get(obj, "causes", []) ++
                Map.get(obj, "effects", []) ++
                Map.get(obj, "context", []) ++
                Map.get(obj, "mechanism", [])

            case Map.get(obj, "refines") do
              refines when is_binary(refines) and refines != "" -> base ++ [refines]
              _ -> base
            end

          "realizable" ->
            [Map.get(obj, "bearer")]

          _ ->
            []
        end

      Enum.reduce(refs, out, fn ref, out ->
        if is_binary(ref) and ref != "" and not Map.has_key?(store.objects, ref) do
          out ++
            [%{"id" => Map.fetch!(obj, "id"), "kind" => "dangling_reference", "ref" => ref}]
        else
          out
        end
      end)
    end)
  end

  # conflict: pairs of claims satisfying the formal test (rule 6).
  defp conflict_gaps(out, objects_in_order) do
    cros = Enum.filter(objects_in_order, &(Map.get(&1, "type") == "causal_relation_object"))

    out ++
      (cros
       |> ordered_pairs()
       |> Enum.filter(fn {a, b} -> Semantics.conflicts(a, b) end)
       |> Enum.map(fn {a, b} ->
         %{"kind" => "conflict", "a" => Map.fetch!(a, "id"), "b" => Map.fetch!(b, "id")}
       end))
  end

  defp ordered_pairs([]), do: []
  defp ordered_pairs([head | tail]), do: Enum.map(tail, &{head, &1}) ++ ordered_pairs(tail)
end
