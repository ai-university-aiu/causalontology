# The Causalontology conformance runner for causalontology-elixir.
#
# Runs every vector in conformance/vectors/ against the Elixir binding. An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure.
#
# Standalone script: it Code.require_file's the lib modules directly, so no
# mix compile is needed — `cd bindings/elixir && elixir conformance.exs`.
#
# The vectors are frozen at specification 1.0.0: they carry concrete 64-hex
# identifiers and real Ed25519 keys, which pass through the (retained)
# normalization unchanged; behavioral vectors derive deterministic keypairs
# from sha256("key:" <> name), exactly as the Python harness does.

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

  @sym_regex ~r/^(occ|cro|cnt|rlz|ast|enr|ret|suc|ed25519):/
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
      "causes" => [sym("occ:c")],
      "effects" => [sym("occ:e")],
      "temporal" => g["temporal"]
    }

    Semantics.admissible(cro, g["elapsed_seconds"])
  end

  # -------------------------------------------------------------------------
  # the 38 vectors
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
    semantics_fails(14, "dmin")
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
    dog = sym("cnt:dog")
    mam = sym("cnt:mammal")
    ani = sym("cnt:animal")

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
      "type" => "cro",
      "causes" => [sym("occ:A")],
      "effects" => [sym("occ:B")],
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
          "about" => sym("cro:demo"),
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
          "about" => sym("cro:demo"),
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
      Store.put(s, %{"type" => "cro", "causes" => [sym("occ:A")], "effects" => [sym("occ:B")]})

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
        %{"about" => sym("cro:claim"), "evidence_type" => "observation", "confidence" => 0.9},
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
    assert!(Store.assertions_about(s, sym("cro:claim")) == [], "succession lineage not honored")
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
    a = sym("occ:A")
    b = sym("occ:B")
    c = sym("occ:C")
    d = sym("occ:D")
    m1 = %{"id" => sym("cro:m1"), "causes" => [a], "effects" => [b]}
    m2 = %{"id" => sym("cro:m2"), "causes" => [b], "effects" => [c]}
    m3 = %{"id" => sym("cro:m3"), "causes" => [d], "effects" => [c]}
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
      Store.put(s, %{"type" => "cro", "causes" => [sym("occ:A")], "effects" => [sym("occ:B")]})

    gap_ids = Enum.map(Store.gaps(s, "missing_field"), & &1["id"])
    assert!(p in gap_ids, "the degenerate claim must be a visible gap")

    {:ok, s, r} =
      Store.put(s, %{
        "type" => "cro",
        "causes" => [sym("occ:A")],
        "effects" => [sym("occ:B")],
        "temporal" => %{"dmin" => 0, "dmax" => 1, "unit" => "seconds"},
        "modality" => "sufficient",
        "refines" => p
      })

    gap_ids = Enum.map(Store.gaps(s, "missing_field"), & &1["id"])
    assert!(p not in gap_ids, "the gap did not close")
    assert!(r not in gap_ids, "the refinement itself must be complete")
  end

  # -------------------------------------------------------------------------

  def main do
    IO.puts("causalontology-elixir conformance run")
    IO.write("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ")
    internal_checks()
    IO.puts("ok")

    failures =
      Enum.reduce(1..38, 0, fn n, failures ->
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

    total = 38
    IO.puts(String.duplicate("-", 60))
    IO.puts("#{total - failures}/#{total} vectors passed")

    if failures > 0 do
      System.halt(1)
    end

    IO.puts(
      "causalontology-elixir is CONFORMANT to the suite " <>
        "(vectors frozen at specification 1.0.0)."
    )
  end
end

Conformance.main()
