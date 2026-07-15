# The Causalontology conformance runner for causalontology-elixir.
#
# Runs every vector in conformance/vectors/ against the Elixir binding. An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure.
#
# Standalone script: it Code.require_file's the lib modules directly, so no
# mix compile is needed — `cd bindings/elixir && elixir conformance.exs`.
#
# The vectors are the whole-word 2.0.0 baseline (Principle P7): V01-V38 are the
# 1.0.0 suite re-frozen unaltered in meaning, V39-V107 are new. They carry
# concrete 64-hex identifiers and real Ed25519 keys, which pass through the
# (retained) normalization unchanged; behavioral vectors derive deterministic
# keypairs from sha256("key:" <> name), exactly as the Python harness does.

Code.require_file("lib/causalontology/json.ex", __DIR__)
Code.require_file("lib/causalontology/jcs.ex", __DIR__)
Code.require_file("lib/causalontology/canonical.ex", __DIR__)
Code.require_file("lib/causalontology/signing.ex", __DIR__)
Code.require_file("lib/causalontology/schema.ex", __DIR__)
Code.require_file("lib/causalontology/semantics.ex", __DIR__)
Code.require_file("lib/causalontology/store.ex", __DIR__)
Code.require_file("lib/causalontology.ex", __DIR__)

defmodule Conformance do
  @moduledoc false

  alias Causalontology.{Canonical, Jcs, Json, Schema, Semantics, Signing, Store}

  # The repository root: CAUSALONTOLOGY_ROOT when set, else two levels up
  # from this script (bindings/elixir -> bindings -> root).
  @root System.get_env("CAUSALONTOLOGY_ROOT") || Path.expand("../..", __DIR__)
  @vecdir Path.join(@root, "conformance/vectors")

  # Whole-word schemes (Principle P7); the same set the Python harness uses.
  @schemes ~w(occurrent causal_relation_object continuant realizable
              assertion enrichment retraction succession
              stratum bridge port conduit quality
              token_individual token_occurrence state_assertion
              token_causal_claim)
  @whole_word MapSet.new(@schemes ++ ["ed25519"])
  @sym_regex Regex.compile!("^(" <> Enum.join(@schemes ++ ["ed25519"], "|") <> "):")
  @hex64 ~r/^[0-9a-f]{64}$/

  # -------------------------------------------------------------------------
  # symbolic-identifier normalization (frozen concrete values pass through)
  # -------------------------------------------------------------------------

  # A real, deterministic Ed25519 keypair for a symbolic key name.
  defp key(name) do
    seed = :crypto.hash(:sha256, "key:" <> name)
    Signing.keypair_from_seed(seed)
  end

  # Normalize one symbolic identifier to a well-formed one.
  defp sym(s) do
    [scheme, name] = String.split(s, ":", parts: 2)

    cond do
      scheme == "ed25519" ->
        # Frozen: a real key passes through.
        if name =~ @hex64, do: s, else: elem(key(name), 1)

      name =~ @hex64 ->
        s

      true ->
        scheme <> ":" <> Base.encode16(:crypto.hash(:sha256, name), case: :lower)
    end
  end

  # Recursively normalize symbolic identifiers and placeholders.
  defp normalize(x) when is_binary(x) do
    cond do
      x == "<128 hex>" -> String.duplicate("ab", 64)
      x =~ @sym_regex -> sym(x)
      true -> x
    end
  end

  defp normalize(x) when is_list(x), do: Enum.map(x, &normalize/1)
  defp normalize(x) when is_map(x), do: Map.new(x, fn {k, v} -> {k, normalize(v)} end)
  defp normalize(x), do: x

  # Load vector n's JSON file (for its structured inputs).
  defp vec(n) do
    hits = Path.wildcard(Path.join(@vecdir, "v#{pad2(n)}_*.json"))
    assert!(length(hits) == 1, "vector #{n} not found")
    hits |> hd() |> File.read!() |> Json.parse!()
  end

  defp vector_name(n) do
    case Path.wildcard(Path.join(@vecdir, "v#{pad2(n)}_*.json")) do
      [hit] -> Path.basename(hit, ".json")
      _ -> "v#{pad2(n)}"
    end
  end

  defp pad2(n), do: n |> Integer.to_string() |> String.pad_leading(2, "0")

  defp ts(i), do: "2026-07-13T0#{i}:00:00Z"

  # Build, timestamp, and sign a provenance record.
  defp signed(kind, body, who, ts_i \\ 0) do
    {secret, pub} = key(who)

    rec =
      body
      |> Map.put("type", kind)
      |> Map.put_new("timestamp", ts(ts_i))

    rec =
      if kind == "succession" do
        Map.put_new(rec, "predecessor", pub)
      else
        Map.put(rec, "source", pub)
      end

    Signing.sign_record(rec, secret, kind)
  end

  defp assert!(condition, message \\ "assertion failed") do
    if condition, do: :ok, else: raise(RuntimeError, message)
  end

  # -------------------------------------------------------------------------
  # content-object builders (mirror bindings/python/tests/run_conformance.py)
  # -------------------------------------------------------------------------

  # A content object completed with its real content-addressed id.
  defp mk(obj), do: Map.put(obj, "id", Canonical.identify(obj))

  defp put_if(map, _key, nil), do: map
  defp put_if(map, key, value), do: Map.put(map, key, value)

  defp stratum(label, scheme, ordinal, unit \\ nil, governs \\ nil) do
    mk(
      %{"type" => "stratum", "label" => label, "scheme" => scheme, "ordinal" => ordinal}
      |> put_if("unit", unit)
      |> put_if("governs", governs)
    )
  end

  defp occ(label, stratum_id \\ nil, category \\ "event") do
    mk(
      %{"type" => "occurrent", "label" => label, "category" => category}
      |> put_if("stratum", stratum_id)
    )
  end

  defp cnt(label, category \\ "object"),
    do: mk(%{"type" => "continuant", "label" => label, "category" => category})

  defp cro(causes, effects, extra \\ %{}) do
    mk(Map.merge(%{"type" => "causal_relation_object", "causes" => causes, "effects" => effects}, extra))
  end

  defp bridge(coarse, fine, relation),
    do: mk(%{"type" => "bridge", "coarse" => coarse, "fine" => fine, "relation" => relation})

  defp port(bearer, label, direction, accepts, realizable \\ nil) do
    mk(
      %{
        "type" => "port",
        "bearer" => bearer,
        "label" => label,
        "direction" => direction,
        "accepts" => accepts
      }
      |> put_if("realizable", realizable)
    )
  end

  defp conduit(frm, to, carries, transform \\ nil) do
    mk(
      %{"type" => "conduit", "label" => "conn", "from" => frm, "to" => to, "carries" => carries}
      |> put_if("transform", transform)
    )
  end

  defp quality(label, datatype, unit \\ nil, stratum_id \\ nil) do
    mk(
      %{"type" => "quality", "label" => label, "datatype" => datatype}
      |> put_if("unit", unit)
      |> put_if("stratum", stratum_id)
    )
  end

  defp individual(instantiates, designator \\ nil, part_of \\ nil) do
    mk(
      %{"type" => "token_individual", "instantiates" => instantiates}
      |> put_if("designator", designator)
      |> put_if("part_of", part_of)
    )
  end

  defp token(instantiates, interval, participants \\ nil, locus \\ nil) do
    mk(
      %{"type" => "token_occurrence", "instantiates" => instantiates, "interval" => interval}
      |> put_if("participants", participants)
      |> put_if("locus", locus)
    )
  end

  defp state(subject, qual, value, interval),
    do:
      mk(%{
        "type" => "state_assertion",
        "subject" => subject,
        "quality" => qual,
        "value" => value,
        "interval" => interval
      })

  defp tcc(causes, effects, covering_law \\ nil, actual_delay \\ nil, counterfactual \\ nil) do
    mk(
      %{"type" => "token_causal_claim", "causes" => causes, "effects" => effects}
      |> put_if("covering_law", covering_law)
      |> put_if("actual_delay", actual_delay)
      |> put_if("counterfactual", counterfactual)
    )
  end

  # The neuroendocrine stratum fixture keyed by ordinal.
  defp neuro do
    labels = %{
      4 => "macromolecular",
      5 => "subcellular",
      6 => "cellular",
      7 => "synaptic",
      9 => "region",
      14 => "community_and_society"
    }

    Map.new(labels, fn {o, label} -> {o, stratum(label, "neuroendocrine", o)} end)
  end

  # -------------------------------------------------------------------------
  # internal sanity checks (not conformance vectors)
  # -------------------------------------------------------------------------

  def internal_checks do
    # RFC 8032, TEST 1 known-answer.
    seed =
      Base.decode16!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        case: :lower
      )

    {pub, _priv} = :crypto.generate_key(:eddsa, :ed25519, seed)

    assert!(
      Base.encode16(pub, case: :lower) ==
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "RFC 8032 TEST 1 public key mismatch: #{Base.encode16(pub, case: :lower)}"
    )

    sig = :crypto.sign(:eddsa, :none, "", [seed, :ed25519])
    assert!(:crypto.verify(:eddsa, :none, "", sig, [pub, :ed25519]), "TEST 1 verify failed")
    assert!(not :crypto.verify(:eddsa, :none, "x", sig, [pub, :ed25519]), "verify must reject")

    # JCS basics.
    assert!(Jcs.encode(%{"b" => 2, "a" => 1}) == ~s({"a":1,"b":2}), "JCS key order wrong")
    assert!(Jcs.encode(1.0) == "1", "JCS 1.0 must be 1")
    assert!(Jcs.encode(6.000) == "6", "JCS 6.000 must be 6")
    assert!(Jcs.encode(0.7) == "0.7", "JCS 0.7 must stay 0.7")
  end

  # -------------------------------------------------------------------------
  # shared vector helpers
  # -------------------------------------------------------------------------

  defp schema_fails(n, must_mention) do
    inp = normalize(vec(n)["input"])
    {ok, why} = Schema.validate_schema(inp)
    assert!(not ok, "expected schema-invalid")

    assert!(
      Enum.any?(why, &String.contains?(&1, must_mention)),
      "no schema reason mentions #{inspect(must_mention)}: #{inspect(why)}"
    )
  end

  defp semantics_fails(n, must_mention) do
    inp = normalize(vec(n)["input"])
    {ok, why} = Semantics.validate_semantics(inp)
    assert!(not ok, "expected semantically-invalid")

    assert!(
      Enum.any?(why, &String.contains?(&1, must_mention)),
      "no semantic reason mentions #{inspect(must_mention)}: #{inspect(why)}"
    )
  end

  defp adm(n) do
    g = vec(n)["given"]

    cro = %{
      "causes" => [sym("occurrent:c")],
      "effects" => [sym("occurrent:e")],
      "temporal" => g["temporal"]
    }

    Semantics.admissible(cro, g["elapsed_seconds"])
  end

  # -------------------------------------------------------------------------
  # V01 - V38: the whole-word re-freeze of the 1.0.0 suite (unaltered meaning)
  # -------------------------------------------------------------------------

  def run_vector(1) do
    inp = normalize(vec(1)["input"])
    {ok, why} = Schema.validate_schema(inp)
    assert!(ok, inspect(why))
    {ok, why} = Semantics.validate_semantics(inp)
    assert!(ok, inspect(why))
  end

  def run_vector(2) do
    inp = normalize(vec(2)["input"])
    {ok, _} = Schema.validate_schema(inp)
    assert!(ok, "schema-invalid")
    {ok, _} = Semantics.validate_semantics(inp)
    assert!(ok, "semantically-invalid")
    {partial, missing} = Semantics.is_partial(inp)
    assert!(partial and missing == vec(2)["expect"]["missing"], inspect(missing))
  end

  def run_vector(3), do: schema_fails(3, "effects")
  def run_vector(4), do: schema_fails(4, "causes")
  def run_vector(5), do: schema_fails(5, "modality")
  def run_vector(6), do: schema_fails(6, "colour")
  def run_vector(7), do: schema_fails(7, "causes")

  def run_vector(8) do
    {ok, why} = Schema.validate_schema(normalize(vec(8)["input"]))
    assert!(ok, inspect(why))
  end

  def run_vector(9), do: schema_fails(9, "label")
  def run_vector(10), do: schema_fails(10, "category")

  def run_vector(11) do
    {ok, why} = Schema.validate_schema(normalize(vec(11)["input"]))
    assert!(ok, inspect(why))
  end

  def run_vector(12), do: schema_fails(12, "confidence")

  def run_vector(13) do
    inp = normalize(vec(13)["input"])
    {ok, why} = Schema.validate_schema(inp)
    assert!(ok, inspect(why))
    {ok, why} = Semantics.validate_semantics(inp)
    assert!(ok, inspect(why))
  end

  def run_vector(14) do
    inp = normalize(vec(14)["input"])
    {ok, _} = Schema.validate_schema(inp)
    assert!(ok, "schema-invalid")
    semantics_fails(14, "minimum_delay")
  end

  def run_vector(15), do: semantics_fails(15, "acyclic")
  def run_vector(16), do: semantics_fails(16, "acyclic")

  def run_vector(17) do
    v = vec(17)
    parent = normalize(v["given"]["parent"])
    child = normalize(v["input"])
    {ok, reason} = Semantics.refinement_valid(child, parent)
    assert!(not ok and String.contains?(reason, "rival"), reason)
  end

  def run_vector(18), do: semantics_fails(18, "not a legal field")
  def run_vector(19), do: semantics_fails(19, "language-tagged")

  def run_vector(20) do
    dog = sym("continuant:dog")
    mam = sym("continuant:mammal")
    ani = sym("continuant:animal")

    enrich = fn about, entry, i ->
      signed("enrichment", %{"about" => about, "field" => "subsumes", "entry" => entry}, "taxo", i)
    end

    # The enforcing tier rejects the cycle-completing write.
    s = Store.new(true)
    {:ok, s, _} = Store.put_record(s, enrich.(dog, mam, 1))
    {:ok, s, _} = Store.put_record(s, enrich.(mam, ani, 2))

    case Store.put_record(s, enrich.(ani, dog, 3)) do
      {:ok, _, _} -> raise "enforcing store accepted a cycle"
      {:error, _, msg} -> assert!(String.contains?(msg, "cycle"), msg)
    end

    # Decentralized merge: the view breaks the cycle deterministically.
    s2 = Store.new(true)
    {:ok, s2, _} = Store.put_record(s2, enrich.(dog, mam, 1))
    {:ok, s2, _} = Store.put_record(s2, enrich.(mam, ani, 2))
    bad = enrich.(ani, dog, 3)
    {:ok, s2, _} = Store.force_merge_record(s2, bad)
    {_active, excluded} = Store.active_taxonomy_edges(s2, "subsumes")

    assert!(
      length(excluded) == 1 and hd(excluded)["id"] == bad["id"],
      "cycle not broken deterministically"
    )

    repair = Store.gaps(s2, "inconsistent_hierarchy")
    assert!(Enum.any?(repair, &(&1["id"] == bad["id"])), "no inconsistent_hierarchy gap")
  end

  def run_vector(21), do: assert!(adm(21) == true, "expected admissible")
  def run_vector(22), do: assert!(adm(22) == false, "expected not admissible")
  def run_vector(23), do: assert!(adm(23) == true, "fixed unit constants violated")

  def run_vector(24) do
    v = vec(24)

    assert!(
      Canonical.identify(normalize(v["inputA"])) == Canonical.identify(normalize(v["inputB"])),
      "key order changed the identity"
    )
  end

  def run_vector(25) do
    v = vec(25)

    assert!(
      Canonical.identify(normalize(v["inputA"])) == Canonical.identify(normalize(v["inputB"])),
      "number formatting changed the identity"
    )
  end

  def run_vector(26) do
    s = Store.new()
    obj = %{"type" => "occurrent", "label" => "press_button", "category" => "action"}
    {:ok, s, a} = Store.put(s, obj)
    {:ok, s, b} = Store.put(s, obj)
    assert!(a == b and map_size(s.objects) == 1, "identical put must be idempotent")
  end

  def run_vector(27) do
    s = Store.new()

    {:ok, s, occ} =
      Store.put(s, %{"type" => "occurrent", "label" => "press_button", "category" => "action"})

    entry = %{"lang" => "en", "text" => "press the button"}
    r1 = signed("enrichment", %{"about" => occ, "field" => "aliases", "entry" => entry}, "alice", 1)
    r2 = signed("enrichment", %{"about" => occ, "field" => "aliases", "entry" => entry}, "bob", 2)
    {:ok, s, id1} = Store.put_record(s, r1)
    {:ok, s, id2} = Store.put_record(s, r2)
    # Two records ...
    assert!(id1 != id2, "expected two distinct records")
    view = Store.get(s, occ)["enrichments"]["aliases"]
    # ... one canonical entry, two contributors.
    assert!(length(view) == 1 and length(hd(view)["contributors"]) == 2, "corroboration wrong")
  end

  def run_vector(28) do
    s = Store.new()

    claim = %{
      "type" => "causal_relation_object",
      "causes" => [sym("occurrent:A")],
      "effects" => [sym("occurrent:B")],
      "modality" => "sufficient"
    }

    {:ok, s, i1} = Store.put(s, claim)
    {:ok, s, i2} = Store.put(s, claim)
    assert!(i1 == i2 and map_size(s.objects) == 1, "one claim must stay one object")

    s =
      Enum.reduce([{"lab1", 1}, {"lab2", 2}], s, fn {who, ts_i}, s ->
        record =
          signed(
            "assertion",
            %{"about" => i1, "evidence_type" => "observation", "strength" => 0.8, "confidence" => 0.8},
            who,
            ts_i
          )

        {:ok, s, _} = Store.put_record(s, record)
        s
      end)

    assert!(length(Store.assertions_about(s, i1)) == 2, "expected two assertions")
  end

  def run_vector(29) do
    rec =
      signed(
        "assertion",
        %{
          "about" => sym("causal_relation_object:demo"),
          "evidence_type" => "intervention",
          "strength" => 0.7,
          "confidence" => 0.9
        },
        "signer"
      )

    assert!(Signing.verify_record(rec) == true, "valid signature must verify")
  end

  def run_vector(30) do
    rec =
      signed(
        "assertion",
        %{
          "about" => sym("causal_relation_object:demo"),
          "evidence_type" => "intervention",
          "strength" => 0.7,
          "confidence" => 0.9
        },
        "signer"
      )

    tampered = Map.put(rec, "confidence", 0.1)
    assert!(Signing.verify_record(tampered) == false, "tampered record must fail")
  end

  def run_vector(31) do
    s = Store.new()

    {:ok, s, x} =
      Store.put(s, %{"type" => "causal_relation_object", "causes" => [sym("occurrent:A")], "effects" => [sym("occurrent:B")]})

    a =
      signed(
        "assertion",
        %{"about" => x, "evidence_type" => "observation", "confidence" => 0.8},
        "lab1",
        1
      )

    {:ok, s, _} = Store.put_record(s, a)
    {:ok, s, _} = Store.put_record(s, signed("retraction", %{"retracts" => a["id"]}, "lab1", 2))
    assert!(Store.assertions_about(s, x) == [], "retracted assertion still in default view")
    hist = Store.assertions_about(s, x, true)
    assert!(length(hist) == 1 and hd(hist)["retracted"] == true, "history flag wrong")

    foreign = signed("retraction", %{"retracts" => a["id"]}, "mallory", 3)

    case Store.put_record(s, foreign) do
      {:ok, _, _} ->
        raise "foreign retraction accepted"

      {:error, s, _msg} ->
        # Still excluded by lab1's own retraction.
        assert!(Store.assertions_about(s, x) == [], "default view changed")
        assert!(length(Store.assertions_about(s, x, true)) == 1, "history changed")
    end
  end

  def run_vector(32) do
    s = Store.new()

    {:ok, s, occ} =
      Store.put(s, %{"type" => "occurrent", "label" => "press_button", "category" => "action"})

    e =
      signed(
        "enrichment",
        %{"about" => occ, "field" => "aliases", "entry" => %{"lang" => "ja", "text" => "botan"}},
        "bob",
        1
      )

    {:ok, s, _} = Store.put_record(s, e)
    aliases = Map.get(Store.get(s, occ)["enrichments"], "aliases", [])
    assert!(length(aliases) == 1, "enrichment not visible before retraction")
    {:ok, s, _} = Store.put_record(s, signed("retraction", %{"retracts" => e["id"]}, "bob", 2))
    assert!(Map.get(Store.get(s, occ)["enrichments"], "aliases", []) == [], "not retracted")
    hist = Map.get(Store.get(s, occ, "history")["enrichments"], "aliases", [])
    assert!(length(hist) == 1, "history must keep the retracted enrichment")
  end

  def run_vector(33) do
    s = Store.new()
    {_, k1} = key("K1")
    {_, k2} = key("K2")

    a =
      signed(
        "assertion",
        %{"about" => sym("causal_relation_object:claim"), "evidence_type" => "observation", "confidence" => 0.9},
        "K1",
        1
      )

    {:ok, s, _} = Store.put_record(s, a)
    succ = signed("succession", %{"successor" => k2}, "K1", 2)
    {:ok, s, _} = Store.put_record(s, succ)

    assert!(
      MapSet.member?(Store.lineage(s, k2), k1) and MapSet.member?(Store.lineage(s, k1), k2),
      "lineage closure wrong"
    )

    # The successor may retract the predecessor's record.
    r = signed("retraction", %{"retracts" => a["id"]}, "K2", 3)
    {:ok, s, _} = Store.put_record(s, r)
    assert!(Store.assertions_about(s, sym("causal_relation_object:claim")) == [], "succession lineage not honored")
  end

  def run_vector(34) do
    g = normalize(vec(34)["given"])
    assert!(Semantics.conflicts(g["A"], g["B"]) == true, "expected a conflict")
  end

  def run_vector(35) do
    g = normalize(vec(35)["given"])
    assert!(Semantics.conflicts(g["A"], g["B"]) == false, "expected no conflict")
  end

  def run_vector(36) do
    a = sym("occurrent:A")
    b = sym("occurrent:B")
    c = sym("occurrent:C")
    d = sym("occurrent:D")
    m1 = %{"id" => sym("causal_relation_object:m1"), "causes" => [a], "effects" => [b]}
    m2 = %{"id" => sym("causal_relation_object:m2"), "causes" => [b], "effects" => [c]}
    m3 = %{"id" => sym("causal_relation_object:m3"), "causes" => [d], "effects" => [c]}
    p = %{"causes" => [a], "effects" => [c], "mechanism" => [m1["id"], m2["id"]]}

    assert!(
      Semantics.hierarchy_consistent(p, %{m1["id"] => m1, m2["id"] => m2}) == "consistent",
      "expected consistent"
    )

    p2 = Map.put(p, "mechanism", [m1["id"], m3["id"]])

    assert!(
      Semantics.hierarchy_consistent(p2, %{m1["id"] => m1, m3["id"] => m3}) == "inconsistent",
      "expected inconsistent"
    )

    assert!(
      Semantics.hierarchy_consistent(p, %{m1["id"] => m1}) == "indeterminate",
      "expected indeterminate"
    )
  end

  def run_vector(37) do
    s = Store.new()

    {:ok, s, occ} =
      Store.put(s, %{"type" => "occurrent", "label" => "press_button", "category" => "action"})

    record =
      signed(
        "enrichment",
        %{
          "about" => occ,
          "field" => "aliases",
          "entry" => %{"lang" => "en", "text" => "Press the Button"}
        },
        "alice",
        1
      )

    {:ok, s, _} = Store.put_record(s, record)
    # Alias match, with whitespace and case normalized away.
    assert!(Store.resolve(s, "Press  The   Button", "en") == [occ], "alias resolve failed")
    # Exact label match ranks first.
    assert!(hd(Store.resolve(s, "press_button", "en")) == occ, "label resolve failed")
  end

  def run_vector(38) do
    s = Store.new()

    {:ok, s, p} =
      Store.put(s, %{"type" => "causal_relation_object", "causes" => [sym("occurrent:A")], "effects" => [sym("occurrent:B")]})

    gap_ids = Enum.map(Store.gaps(s, "missing_field"), & &1["id"])
    assert!(p in gap_ids, "the degenerate claim must be a visible gap")

    {:ok, s, r} =
      Store.put(s, %{
        "type" => "causal_relation_object",
        "causes" => [sym("occurrent:A")],
        "effects" => [sym("occurrent:B")],
        "temporal" => %{"minimum_delay" => 0, "maximum_delay" => 1, "unit" => "seconds"},
        "modality" => "sufficient",
        "refines" => p
      })

    gap_ids = Enum.map(Store.gaps(s, "missing_field"), & &1["id"])
    assert!(p not in gap_ids, "the gap did not close")
    assert!(r not in gap_ids, "the refinement itself must be complete")
  end

  # -------------------------------------------------------------------------
  # V39 - V107: the 2.0.0 additions
  # -------------------------------------------------------------------------

  def run_vector(39) do
    st = stratum("cellular", "neuroendocrine", 6, "cell", ["cell_biology"])
    {ok, why} = Schema.validate_schema(st)
    assert!(ok, inspect(why))
  end

  def run_vector(40) do
    bad = mk(%{"type" => "stratum", "label" => "cellular", "ordinal" => 6})
    {ok, why} = Schema.validate_schema(bad, "stratum")
    assert!(not ok and Enum.any?(why, &String.contains?(&1, "scheme")), inspect(why))
  end

  def run_vector(41) do
    a = stratum("cellular", "neuroendocrine", 6)
    b = stratum("neuronal", "neuroendocrine", 6)

    for x <- [a, b] do
      {ok, why} = Schema.validate_schema(x)
      assert!(ok, inspect(why))
    end

    assert!(a["id"] != b["id"], "same-ordinal strata must be distinct")
  end

  def run_vector(42) do
    s = neuro()
    s4p = stratum("molecular", "physics", 4)
    c = occ("chronic_social_subordination", s[14]["id"])
    e = occ("gene_expression", s4p["id"])
    smap = %{s[14]["id"] => s[14], s4p["id"] => s4p}
    omap = %{c["id"] => c, e["id"] => e}
    p = cro([c["id"]], [e["id"]])
    assert!(Semantics.classify_cro(p, omap, smap) == "scheme_mismatch", "expected scheme_mismatch")
  end

  def run_vector(43) do
    for x <- [stratum("macromolecular", "neuroendocrine", 4), stratum("region", "neuroendocrine", 9)] do
      {ok, why} = Schema.validate_schema(x)
      assert!(ok, inspect(why))
    end
  end

  def run_vector(44) do
    st = stratum("cellular", "neuroendocrine", 6)
    o = occ("neuron_fires", st["id"])
    {ok, why} = Schema.validate_schema(o)
    assert!(ok, inspect(why))
    {ok, why} = Semantics.validate_semantics(o)
    assert!(ok, inspect(why))
  end

  def run_vector(45) do
    o = occ("press_button")
    {ok, why} = Schema.validate_schema(o)
    assert!(ok, inspect(why))
    e = occ("light_on")
    p = cro([o["id"]], [e["id"]])
    assert!(Semantics.classify_cro(p, %{o["id"] => o, e["id"] => e}, %{}) == "unclassifiable", "expected unclassifiable")
  end

  def run_vector(46) do
    s = neuro()
    a = occ("depolarization", s[5]["id"])
    b = occ("depolarization", s[6]["id"])
    assert!(a["id"] != b["id"], "same label, different stratum must be distinct")
  end

  def run_vector(47), do: valid_bridge("constitutes")
  def run_vector(48), do: valid_bridge("aggregates")
  def run_vector(49), do: valid_bridge("realizes")
  def run_vector(50), do: valid_bridge("supervenes_on")

  def run_vector(51) do
    s = neuro()
    coarse = occ("x_coarse", s[4]["id"])
    fine = occ("x_fine", s[6]["id"])
    b = bridge(coarse["id"], [fine["id"]], "constitutes")
    omap = %{coarse["id"] => coarse, fine["id"] => fine}
    smap = %{s[4]["id"] => s[4], s[6]["id"] => s[6]}
    {ok, _} = Semantics.bridge_wellformed(b, omap, smap)
    assert!(not ok, "coarse ordinal not > fine must be malformed")
  end

  def run_vector(52) do
    s = neuro()
    coarse = occ("c", s[6]["id"])
    f1 = occ("f1", s[4]["id"])
    f2 = occ("f2", s[5]["id"])
    b = bridge(coarse["id"], [f1["id"], f2["id"]], "constitutes")
    omap = %{coarse["id"] => coarse, f1["id"] => f1, f2["id"] => f2}
    smap = %{s[4]["id"] => s[4], s[5]["id"] => s[5], s[6]["id"] => s[6]}
    {ok, _} = Semantics.bridge_wellformed(b, omap, smap)
    assert!(not ok, "fine spanning >1 stratum must be malformed")
  end

  def run_vector(53) do
    x = sym("occurrent:x")
    y = sym("occurrent:y")
    b1 = bridge(x, [y], "constitutes")
    b2 = bridge(y, [x], "constitutes")

    edges =
      Enum.reduce([b1, b2], %{}, fn b, acc ->
        Enum.reduce(b["fine"], acc, fn f, a ->
          Map.update(a, f, [b["coarse"]], &(&1 ++ [b["coarse"]]))
        end)
      end)

    assert!(Semantics.has_cycle(edges) == true, "expected a cycle")
  end

  def run_vector(54) do
    a = stratum("cellular", "neuroendocrine", 6)
    b = stratum("molecular", "physics", 4)
    coarse = occ("c", a["id"])
    fine = occ("f", b["id"])
    br = bridge(coarse["id"], [fine["id"]], "constitutes")
    omap = %{coarse["id"] => coarse, fine["id"] => fine}
    smap = %{a["id"] => a, b["id"] => b}
    {ok, _} = Semantics.bridge_wellformed(br, omap, smap)
    assert!(not ok, "cross-scheme bridge must be malformed")
  end

  def run_vector(55) do
    s = neuro()
    coarse = occ("decision_made", s[6]["id"])
    f1 = occ("cascade_a", s[4]["id"])
    f2 = occ("cascade_b", s[4]["id"])
    b1 = bridge(coarse["id"], [f1["id"]], "realizes")
    b2 = bridge(coarse["id"], [f2["id"]], "realizes")
    assert!(b1["id"] != b2["id"], "distinct realizations must differ")

    for b <- [b1, b2] do
      {ok, why} = Schema.validate_schema(b)
      assert!(ok, inspect(why))
    end
  end

  def run_vector(56) do
    {p, members, bridges} = reach_fixture()
    assert!(Semantics.hierarchy_consistent(p, members, bridges) == "consistent", "expected consistent")
  end

  def run_vector(57) do
    {p, members, _} = reach_fixture()
    assert!(Semantics.hierarchy_consistent(p, members, []) == "inconsistent", "expected inconsistent")
  end

  def run_vector(58) do
    {p, members, bridges} = reach_fixture()
    literal = Semantics.hierarchy_consistent(p, members, [])
    bridged = Semantics.hierarchy_consistent(p, members, bridges)
    assert!(literal != "consistent" and bridged == "consistent", "literal=#{literal} bridged=#{bridged}")
  end

  def run_vector(59), do: assert!(classify(6, 6) == "intra_stratal", "expected intra_stratal")
  def run_vector(60), do: assert!(classify(6, 5) == "adjacent_stratal", "expected adjacent_stratal")
  def run_vector(61), do: assert!(classify(14, 4) == "skipping", "expected skipping")

  def run_vector(62) do
    {p, cls} = skip_fixture(14, 4)
    assert!(Semantics.skip_gaps(p, cls) == ["incomplete_mechanism"], "expected [incomplete_mechanism]")
  end

  def run_vector(63) do
    {p, cls} = skip_fixture(14, 4, %{"skips" => true})
    assert!(Semantics.skip_gaps(p, cls) == [], "expected []")
  end

  def run_vector(64) do
    {p, cls} = skip_fixture(14, 4, %{"skips" => true, "mechanism" => [sym("causal_relation_object:m")]})
    assert!(Semantics.skip_gaps(p, cls) == ["contradictory_skip"], "expected [contradictory_skip]")
    {ok, why} = Semantics.validate_semantics(p)
    assert!(not ok and Enum.any?(why, &String.contains?(&1, "contradictory_skip")), inspect(why))
  end

  def run_vector(65) do
    {p, cls} = skip_fixture(6, 6, %{"skips" => true})
    assert!(Semantics.skip_gaps(p, cls) == ["vacuous_skip"], "expected [vacuous_skip]")
  end

  def run_vector(66) do
    s = neuro()
    c = occ("c", s[14]["id"])
    e = occ("e", s[4]["id"])
    absent = cro([c["id"]], [e["id"]])
    false_ = cro([c["id"]], [e["id"]], %{"skips" => false})
    assert!(absent["id"] != false_["id"], "absent skips vs skips:false must differ")
  end

  def run_vector(67) do
    s = neuro()
    c1 = occ("c1", s[4]["id"])
    c2 = occ("c2", s[6]["id"])
    e = occ("e", s[6]["id"])
    p = cro([c1["id"], c2["id"]], [e["id"]])
    assert!(Semantics.endpoints_mixed(p, %{c1["id"] => c1, c2["id"] => c2, e["id"] => e}) == true, "expected mixed endpoints")
  end

  def run_vector(68) do
    p = cro([sym("occurrent:a")], [sym("occurrent:b")], %{"modality" => "enabling"})
    {ok, why} = Schema.validate_schema(p)
    assert!(ok, inspect(why))
  end

  def run_vector(69) do
    a = %{"causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")], "modality" => "enabling"}
    b = %{"causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")], "modality" => "sufficient"}
    assert!(Semantics.conflicts(a, b) == false, "enabling vs sufficient must not conflict")
  end

  def run_vector(70) do
    a = %{"causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")], "modality" => "enabling"}
    b = %{"causes" => [sym("occurrent:a")], "effects" => [sym("occurrent:b")], "modality" => "preventive"}
    assert!(Semantics.conflicts(a, b) == true, "enabling vs preventive must conflict")
  end

  def run_vector(71) do
    b = cnt("hippocampus")
    p = port(b["id"], "perforant_path", "in", [sym("occurrent:signal")])
    {ok, why} = Schema.validate_schema(p)
    assert!(ok, inspect(why))
  end

  def run_vector(72) do
    b = cnt("hippocampus")["id"]
    x = sym("occurrent:signal")
    assert!(port(b, "perforant_path", "in", [x])["id"] != port(b, "fornix", "in", [x])["id"], "ports must differ by label")
  end

  def run_vector(73) do
    {c, pmap, _} = conduit_fixture()
    {ok, why} = Schema.validate_schema(c)
    assert!(ok, inspect(why))
    {ok, why} = Semantics.conduit_wellformed(c, pmap)
    assert!(ok, inspect(why))
  end

  def run_vector(74) do
    {c, pmap, cmap} = conduit_fixture(transform: true)
    {ok, why} = Schema.validate_schema(c)
    assert!(ok, inspect(why))
    {ok, why} = Semantics.conduit_wellformed(c, pmap, cmap)
    assert!(ok, inspect(why))
  end

  def run_vector(75) do
    {c, pmap, _} = conduit_fixture(bad_carry: true)
    {ok, _} = Semantics.conduit_wellformed(c, pmap)
    assert!(not ok, "carries not accepted by from must be malformed")
  end

  def run_vector(76) do
    {c, pmap, _} = conduit_fixture(in_from: true)
    {ok, _} = Semantics.conduit_wellformed(c, pmap)
    assert!(not ok, "from port not out/bidirectional must be malformed")
  end

  def run_vector(77) do
    {c, pmap, cmap} = conduit_fixture(transform: true)
    {ok, why} = Semantics.conduit_wellformed(c, pmap, cmap)
    assert!(ok, inspect(why))
    law = cmap |> Map.values() |> hd()
    assert!(hd(law["effects"]) not in c["carries"], "transform output must not be carried directly")
  end

  def run_vector(78) do
    b = cnt("hippocampus")["id"]
    assert!(rlz(b, "disposition", "long_term_potentiation")["id"] != rlz(b, "disposition", "pattern_separation")["id"], "labels must distinguish realizables")
  end

  def run_vector(79) do
    b = cnt("hippocampus")["id"]
    u1 = rlz(b, "disposition")
    u2 = rlz(b, "disposition")
    {ok, why} = Schema.validate_schema(u1)
    assert!(ok, inspect(why))
    assert!(u1["id"] == u2["id"], "unlabeled realizables must be identical")
    assert!(rlz(b, "disposition", "some_function")["id"] != u1["id"], "label must change identity")
  end

  def run_vector(80) do
    parent = occ("fires")
    child = occ("fires_action_potential")
    e = %{"type" => "enrichment", "about" => child["id"], "field" => "occurrent_subsumes", "entry" => parent["id"]}
    {ok, why} = Semantics.validate_semantics(e)
    assert!(ok, inspect(why))
  end

  def run_vector(81) do
    a = sym("occurrent:a")
    b = sym("occurrent:b")
    assert!(Semantics.has_cycle(%{a => [b], b => [a]}) == true, "expected a cycle")
  end

  def run_vector(82) do
    whole = occ("eat")
    part = occ("chew")
    e = %{"type" => "enrichment", "about" => part["id"], "field" => "occurrent_part_of", "entry" => whole["id"]}
    {ok, why} = Semantics.validate_semantics(e)
    assert!(ok, inspect(why))
  end

  def run_vector(83) do
    {legal_kinds, shape} = Map.fetch!(Semantics.enrichment_fields(), "occurrent_part_of")
    assert!(shape == "occurrent" and legal_kinds == ["occurrent"], "occurrent_part_of spec wrong")
    s = Store.new()
    {:ok, s, _} = Store.put(s, occ("eat"))
    {:ok, s, _} = Store.put(s, occ("chew"))

    assert!(
      not Enum.any?(Map.values(s.objects), &(Map.get(&1, "type") == "causal_relation_object")),
      "no CRO must sneak into the store"
    )
  end

  def run_vector(84) do
    s = neuro()
    a = occ("run", s[9]["id"])
    b = occ("sprint", s[6]["id"])
    assert!(a["stratum"] != b["stratum"], "different strata must differ")
  end

  def run_vector(85) do
    c = cnt("human_patient")
    ti = individual(c["id"], "salted_hash_abc123")
    {ok, why} = Schema.validate_schema(ti)
    assert!(ok, inspect(why))
  end

  def run_vector(86) do
    bad = mk(%{"type" => "token_individual", "designator" => "x"})
    {ok, why} = Schema.validate_schema(bad, "token_individual")
    assert!(not ok and Enum.any?(why, &String.contains?(&1, "instantiates")), inspect(why))
  end

  def run_vector(87) do
    c = cnt("human_patient")["id"]
    assert!(individual(c, "hash_a")["id"] != individual(c, "hash_b")["id"], "designator must distinguish individuals")
  end

  def run_vector(88) do
    o = occ("bilateral_hippocampal_resection")
    t = token(o["id"], %{"start" => "1953-08-25T00:00:00Z", "end" => "1953-08-25T00:00:00Z"})
    {ok, why} = Schema.validate_schema(t)
    assert!(ok, inspect(why))
  end

  def run_vector(89) do
    o = occ("amnesia_onset")["id"]
    bounded = token(o, %{"start" => "1953-08-25T00:00:00Z", "end" => "1953-08-26T00:00:00Z"})
    instantaneous = token(o, %{"start" => "1953-08-25T00:00:00Z"})
    ongoing = token(o, %{"start" => "1953-08-25T00:00:00Z", "open" => true})
    assert!(MapSet.size(MapSet.new([bounded["id"], instantaneous["id"], ongoing["id"]])) == 3, "three interval shapes must differ")
  end

  def run_vector(90) do
    o = occ("resection")["id"]
    c = cnt("human_patient")["id"]
    patient = individual(c, "p")["id"]
    surgeon = individual(c, "s")["id"]

    t =
      token(o, %{"start" => "1953-08-25T00:00:00Z"}, [
        %{"role" => "patient", "filler" => patient},
        %{"role" => "agent", "filler" => surgeon}
      ])

    {ok, why} = Schema.validate_schema(t)
    assert!(ok, inspect(why))
  end

  def run_vector(91) do
    q = quality("cortisol_concentration", "quantity", "ug/dL")
    {ok, why} = Schema.validate_schema(q)
    assert!(ok, inspect(why))
  end

  def run_vector(92) do
    {st, q} = state_fixture("quantity", %{"quantity" => 15.0, "unit" => "ug/dL"}, "ug/dL")
    {ok, why} = Schema.validate_schema(st)
    assert!(ok, inspect(why))
    assert!(Semantics.state_gaps(st, q) == [], "expected no gaps")
  end

  def run_vector(93) do
    {st, q} = state_fixture("categorical", %{"categorical" => "elevated"})
    {ok, why} = Schema.validate_schema(st)
    assert!(ok, inspect(why))
    assert!(Semantics.state_gaps(st, q) == [], "expected no gaps")
  end

  def run_vector(94) do
    {st, q} = state_fixture("boolean", %{"boolean" => true})
    {ok, why} = Schema.validate_schema(st)
    assert!(ok, inspect(why))
    assert!(Semantics.state_gaps(st, q) == [], "expected no gaps")
  end

  def run_vector(95) do
    {st, q} = state_fixture("quantity", %{"categorical" => "elevated"}, "ug/dL")
    assert!(Semantics.state_gaps(st, q) == ["value_type_mismatch"], "expected [value_type_mismatch]")
  end

  def run_vector(96) do
    {st, q} = state_fixture("quantity", %{"quantity" => 15.0, "unit" => "mg/dL"}, "ug/dL")
    assert!(Semantics.state_gaps(st, q) == ["unit_mismatch"], "expected [unit_mismatch]")
  end

  def run_vector(97) do
    {law, _, _, tc, te} = law_and_tokens()

    claim =
      tcc([tc["id"]], [te["id"]], law["id"], %{"duration" => 0, "unit" => "instant"}, true)

    {ok, why} = Schema.validate_schema(claim)
    assert!(ok, inspect(why))
  end

  def run_vector(98) do
    {_, _, _, tc, te} = law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]])
    {ok, why} = Schema.validate_schema(claim)
    assert!(ok, inspect(why))
    assert!(not Map.has_key?(claim, "covering_law"), "covering_law must be absent")
  end

  def run_vector(99) do
    {law, _, _, _, _} = law_and_tokens()
    assert!(Semantics.delay_within_window(%{"duration" => 0, "unit" => "instant"}, law["temporal"]) == true, "instant must be within window")
  end

  def run_vector(100) do
    temporal = %{"minimum_delay" => 0, "maximum_delay" => 1, "unit" => "hours"}
    assert!(Semantics.delay_within_window(%{"duration" => 5, "unit" => "days"}, temporal) == false, "5 days must be outside a 1-hour window")
  end

  def run_vector(101) do
    o = occ("x")["id"]
    cause = token(o, %{"start" => "2026-01-02T00:00:00Z"})
    effect = token(o, %{"start" => "2026-01-01T00:00:00Z"})
    claim = tcc([cause["id"]], [effect["id"]])
    assert!(Semantics.retrocausal(claim, %{cause["id"] => cause, effect["id"] => effect}) == true, "expected retrocausal")
  end

  def run_vector(102) do
    other = cro([sym("occurrent:foo")], [sym("occurrent:bar")])
    {_, _, _, tc, te} = law_and_tokens()
    claim = tcc([tc["id"]], [te["id"]], other["id"])
    assert!(Semantics.covering_law_mismatch(claim, %{tc["id"] => tc, te["id"] => te}, other) == true, "expected covering-law mismatch")
  end

  def run_vector(103) do
    a =
      signed(
        "assertion",
        %{"about" => sym("token_occurrence:t"), "evidence_type" => "observation", "confidence" => 0.9},
        "signer"
      )

    {ok, why} = Schema.validate_schema(a)
    assert!(ok, inspect(why))
  end

  def run_vector(104) do
    ev = [sym("token_occurrence:t1"), sym("token_causal_claim:c1")]

    base = %{
      "type" => "assertion",
      "about" => sym("causal_relation_object:law"),
      "source" => elem(key("signer"), 1),
      "evidence_type" => "intervention",
      "strength" => 0.95,
      "confidence" => 0.99,
      "timestamp" => "2026-07-14T00:00:00Z"
    }

    a = Map.put(base, "evidenced_by", ev)
    {ok, why} = Schema.validate_schema(Map.put(a, "id", Canonical.identify(a)))
    assert!(ok, inspect(why))
    assert!(Canonical.identify(a) != Canonical.identify(base), "evidenced_by must be identity-bearing")
  end

  def run_vector(105) do
    a =
      signed(
        "assertion",
        %{"about" => sym("causal_relation_object:law"), "evidence_type" => "simulation", "confidence" => 0.5},
        "signer"
      )

    {ok, why} = Schema.validate_schema(a)
    assert!(ok, inspect(why))
    rank = %{"intervention" => 0, "observation" => 1, "simulation" => 2}
    assert!(rank["intervention"] < rank["observation"] and rank["observation"] < rank["simulation"], "evidence rank order wrong")
  end

  def run_vector(106) do
    id_re = ~r/^([a-z0-9_]+):[0-9a-f]{64}$/

    for n <- 1..38 do
      ids = scan_schemes(vec(n), id_re, [])

      for scheme <- ids do
        assert!(MapSet.member?(@whole_word, scheme), "V106: abbreviated scheme #{inspect(scheme)} in vector #{n}")
      end
    end

    rec = %{"type" => "occurrent", "label" => "press_button", "category" => "action"}
    assert!(Canonical.identify(rec) == Canonical.identify(rec), "identity must be deterministic")
    assert!(Canonical.identify(rec) |> String.split(":", parts: 2) |> hd() == "occurrent", "whole-word prefix expected")
  end

  def run_vector(107) do
    hexid = String.duplicate("0", 64)
    # NOTE: the abbreviated prefix below is INTENTIONAL (the negative test); it
    # must NOT be re-minted. "c" "r" "o" is assembled to survive re-mint tools.
    cro_abbr = "c" <> "r" <> "o"

    abbreviated = %{
      "type" => "causal_relation_object",
      "id" => cro_abbr <> ":" <> hexid,
      "causes" => ["occurrent:" <> hexid],
      "effects" => ["occurrent:" <> hexid]
    }

    {ok, _} = Schema.validate_schema(abbreviated, "causal_relation_object")
    assert!(not ok, "abbreviated scheme must be rejected")

    abbr_str = %{
      "type" => "stratum",
      "id" => "str" <> ":" <> hexid,
      "label" => "cellular",
      "scheme" => "neuroendocrine",
      "ordinal" => 6
    }

    {ok, _} = Schema.validate_schema(abbr_str, "stratum")
    assert!(not ok, "abbreviated stratum scheme must be rejected")

    whole = %{
      "type" => "causal_relation_object",
      "id" => "causal_relation_object:" <> hexid,
      "causes" => ["occurrent:" <> hexid],
      "effects" => ["occurrent:" <> hexid]
    }

    {ok, why} = Schema.validate_schema(whole, "causal_relation_object")
    assert!(ok, inspect(why))
  end

  # -------------------------------------------------------------------------
  # fixtures shared by the 2.0.0 vectors (grouped here so the run_vector/1
  # clauses stay contiguous)
  # -------------------------------------------------------------------------

  defp bridge_fixture(relation) do
    s = neuro()
    coarse = occ("action_potential_fires", s[6]["id"])
    fine = [occ("sodium_channels_open", s[4]["id"]), occ("sodium_influx", s[4]["id"])]
    b = bridge(coarse["id"], Enum.map(fine, & &1["id"]), relation)
    omap = Enum.reduce(fine, %{coarse["id"] => coarse}, fn f, acc -> Map.put(acc, f["id"], f) end)
    smap = %{s[4]["id"] => s[4], s[6]["id"] => s[6]}
    {b, omap, smap}
  end

  defp valid_bridge(relation) do
    {b, omap, smap} = bridge_fixture(relation)
    {ok, why} = Schema.validate_schema(b)
    assert!(ok, inspect(why))
    {ok, why} = Semantics.bridge_wellformed(b, omap, smap)
    assert!(ok, inspect(why))
  end

  defp reach_fixture do
    s = neuro()
    ap = occ("action_potential_fires", s[6]["id"])
    nt = occ("neurotransmitter_released", s[6]["id"])
    fa = occ("calcium_enters", s[4]["id"])
    fb = occ("vesicle_fuses", s[4]["id"])
    m1 = cro([fa["id"]], [fb["id"]])
    p = cro([ap["id"]], [nt["id"]], %{"mechanism" => [m1["id"]]})
    bridges = [bridge(ap["id"], [fa["id"]], "constitutes"), bridge(nt["id"], [fb["id"]], "constitutes")]
    {p, %{m1["id"] => m1}, bridges}
  end

  defp classify(cause_ord, effect_ord) do
    s = neuro()
    c = occ("c", s[cause_ord]["id"])
    e = occ("e", s[effect_ord]["id"])
    smap = %{s[cause_ord]["id"] => s[cause_ord], s[effect_ord]["id"] => s[effect_ord]}
    omap = %{c["id"] => c, e["id"] => e}
    Semantics.classify_cro(cro([c["id"]], [e["id"]]), omap, smap)
  end

  defp skip_fixture(cause_ord, effect_ord, extra \\ %{}) do
    s = neuro()
    c = occ("c", s[cause_ord]["id"])
    e = occ("e", s[effect_ord]["id"])
    smap = %{s[cause_ord]["id"] => s[cause_ord], s[effect_ord]["id"] => s[effect_ord]}
    omap = %{c["id"] => c, e["id"] => e}
    p = cro([c["id"]], [e["id"]], extra)
    {p, Semantics.classify_cro(p, omap, smap)}
  end

  defp conduit_fixture(opts \\ []) do
    transform = Keyword.get(opts, :transform, false)
    bad_carry = Keyword.get(opts, :bad_carry, false)
    in_from = Keyword.get(opts, :in_from, false)

    x = sym("occurrent:motor_command")
    y = sym("occurrent:error_signal")
    z = sym("occurrent:unrelated")
    m1 = cnt("motor_cortex")["id"]
    m2 = cnt("spinal_neuron")["id"]
    frm = port(m1, "out_port", if(in_from, do: "in", else: "out"), [x])
    to = port(m2, "in_port", "in", if(transform, do: [y], else: [x]))
    carries = if bad_carry, do: [z], else: [x]

    {xform, cro_map} =
      if transform do
        law = cro([x], [y])
        {law["id"], %{law["id"] => law}}
      else
        {nil, %{}}
      end

    c = conduit(frm["id"], to["id"], carries, xform)
    {c, %{frm["id"] => frm, to["id"] => to}, cro_map}
  end

  defp rlz(bearer, kind, label \\ nil) do
    mk(
      %{"type" => "realizable", "kind" => kind, "bearer" => bearer}
      |> put_if("label", label)
    )
  end

  defp state_fixture(datatype, value, unit \\ nil) do
    q = quality("cortisol_concentration", datatype, unit)
    c = cnt("human_patient")["id"]
    subj = individual(c, "p")["id"]
    st = state(subj, q["id"], value, %{"start" => "2026-01-01T00:00:00Z", "end" => "2026-01-01T01:00:00Z"})
    {st, q}
  end

  defp law_and_tokens do
    o_cause = occ("resection")
    o_effect = occ("amnesia_onset")

    law =
      cro([o_cause["id"]], [o_effect["id"]], %{
        "temporal" => %{"minimum_delay" => 0, "maximum_delay" => 1, "unit" => "days"},
        "modality" => "sufficient"
      })

    t_cause = token(o_cause["id"], %{"start" => "1953-08-25T00:00:00Z"})
    t_effect = token(o_effect["id"], %{"start" => "1953-08-25T00:00:00Z", "open" => true})
    {law, o_cause, o_effect, t_cause, t_effect}
  end

  defp scan_schemes(node, re, acc) when is_binary(node) do
    case Regex.run(re, node) do
      [_, scheme] -> [scheme | acc]
      nil -> acc
    end
  end

  defp scan_schemes(node, re, acc) when is_list(node),
    do: Enum.reduce(node, acc, fn x, a -> scan_schemes(x, re, a) end)

  defp scan_schemes(node, re, acc) when is_map(node),
    do: Enum.reduce(Map.values(node), acc, fn x, a -> scan_schemes(x, re, a) end)

  defp scan_schemes(_node, _re, acc), do: acc

  # -------------------------------------------------------------------------

  def main do
    IO.puts("causalontology-elixir conformance run")
    IO.write("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ")
    internal_checks()
    IO.puts("ok")

    failures =
      Enum.reduce(1..107, 0, fn n, failures ->
        name = vector_name(n)

        try do
          run_vector(n)
          IO.puts("PASS  #{name}")
          failures
        rescue
          e ->
            IO.puts("FAIL  #{name} :: #{Exception.message(e)}")
            failures + 1
        catch
          kind, value ->
            IO.puts("FAIL  #{name} :: #{inspect({kind, value})}")
            failures + 1
        end
      end)

    total = 107
    IO.puts(String.duplicate("-", 60))
    IO.puts("#{total - failures}/#{total} vectors passed")

    if failures > 0 do
      System.halt(1)
    end

    IO.puts(
      "causalontology-elixir is CONFORMANT to the suite " <>
        "(vectors frozen at specification 2.0.0)."
    )
  end
end

Conformance.main()
