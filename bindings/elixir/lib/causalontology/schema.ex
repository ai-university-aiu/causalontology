defmodule Causalontology.Schema do
  @moduledoc """
  Schema validation against spec/schema/*.schema.json.

  A deliberately small interpreter for exactly the JSON Schema keywords the
  seventeen Causalontology schemas use: type, const, enum, pattern, required,
  properties, additionalProperties, items, minItems, minLength, minimum,
  maximum, oneOf, local $ref (#/$defs/...), and cross-file $ref to a sibling
  schema (https://causalontology.org/schema/<file>.schema.json#/...). "format"
  is treated as an annotation, as the 2020-12 draft does by default.
  """

  alias Causalontology.{Canonical, Json}

  # kind -> schema file. Three token kinds keep their original 1.0.0-reserved
  # file names (individual/token/state); the id scheme is the whole word.
  @schema_files %{
    "occurrent" => "occurrent.schema.json",
    "causal_relation_object" => "causal_relation_object.schema.json",
    "continuant" => "continuant.schema.json",
    "realizable" => "realizable.schema.json",
    "stratum" => "stratum.schema.json",
    "bridge" => "bridge.schema.json",
    "port" => "port.schema.json",
    "conduit" => "conduit.schema.json",
    "quality" => "quality.schema.json",
    "token_individual" => "individual.schema.json",
    "token_occurrence" => "token.schema.json",
    "state_assertion" => "state.schema.json",
    "token_causal_claim" => "token_causal_claim.schema.json",
    "assertion" => "assertion.schema.json",
    "enrichment" => "enrichment.schema.json",
    "retraction" => "retraction.schema.json",
    "succession" => "succession.schema.json"
  }

  @base "https://causalontology.org/schema/"

  @doc "{ok, reasons} — structural validity against the kind's JSON Schema."
  def validate_schema(obj, kind \\ nil) do
    kind = kind || Canonical.infer_kind(obj)
    root = load_schema(kind)
    errors = check(obj, root, root, "$", [])
    {errors == [], errors}
  end

  @doc "Load and parse the JSON Schema for a kind."
  def load_schema(kind) do
    file =
      Map.get(@schema_files, kind) ||
        raise(ArgumentError, "unknown kind: #{inspect(kind)}")

    load_file(file)
  end

  # Load and parse a schema file by its bare filename (for cross-file $refs).
  defp load_file(filename) do
    schema_dir() |> Path.join(filename) |> File.read!() |> Json.parse!()
  end

  # The spec directory: the CAUSALONTOLOGY_SPEC environment variable when set
  # (naming the spec/ directory), otherwise resolved relative to this source
  # file (bindings/elixir/lib/causalontology -> repository root -> spec).
  defp schema_dir do
    case System.get_env("CAUSALONTOLOGY_SPEC") do
      nil -> Path.expand("../../../../spec/schema", __DIR__)
      env -> Path.join(env, "schema")
    end
  end

  # ------------------------------------------------------------ the checker

  defp check(value, schema, root, path, errors) do
    {schema, root} = deref(schema, root)

    if Map.has_key?(schema, "oneOf") do
      passing =
        Enum.count(Map.fetch!(schema, "oneOf"), fn sub ->
          check(value, sub, root, path, []) == []
        end)

      if passing == 1 do
        errors
      else
        errors ++ ["#{path}: matches #{passing} of the oneOf branches (need exactly 1)"]
      end
    else
      check_type(value, schema, root, path, errors)
    end
  end

  defp check_type(value, schema, root, path, errors) do
    case Map.get(schema, "type") do
      nil ->
        check_keywords(value, schema, root, path, errors)

      t ->
        if type_ok?(value, t) do
          check_keywords(value, schema, root, path, errors)
        else
          # A type mismatch stops further keyword checks, as in the reference.
          errors ++ ["#{path}: expected #{t}"]
        end
    end
  end

  defp type_ok?(value, "object"), do: is_map(value)
  defp type_ok?(value, "array"), do: is_list(value)
  defp type_ok?(value, "string"), do: is_binary(value)
  # Elixir keeps booleans (atoms) distinct from numbers, so no bool guard is
  # needed here as it is in the Python reference (where bool subclasses int).
  defp type_ok?(value, "number"), do: is_number(value)
  defp type_ok?(value, "integer"), do: is_integer(value)
  defp type_ok?(value, "boolean"), do: is_boolean(value)

  defp check_keywords(value, schema, root, path, errors) do
    errors
    |> check_const(value, schema, path)
    |> check_enum(value, schema, path)
    |> check_pattern(value, schema, path)
    |> check_min_length(value, schema, path)
    |> check_minimum(value, schema, path)
    |> check_maximum(value, schema, path)
    |> check_array(value, schema, root, path)
    |> check_object(value, schema, root, path)
  end

  defp check_const(errors, value, schema, path) do
    case Map.fetch(schema, "const") do
      {:ok, const} when const != value -> errors ++ ["#{path}: must equal #{inspect(const)}"]
      _ -> errors
    end
  end

  defp check_enum(errors, value, schema, path) do
    case Map.fetch(schema, "enum") do
      {:ok, allowed} ->
        if value in allowed do
          errors
        else
          errors ++ ["#{path}: #{inspect(value)} not in enumeration"]
        end

      :error ->
        errors
    end
  end

  defp check_pattern(errors, value, schema, path) do
    with {:ok, pattern} <- Map.fetch(schema, "pattern"),
         true <- is_binary(value),
         false <- Regex.match?(Regex.compile!(pattern), value) do
      errors ++ ["#{path}: #{inspect(value)} does not match #{pattern}"]
    else
      _ -> errors
    end
  end

  defp check_min_length(errors, value, schema, path) do
    with {:ok, min} <- Map.fetch(schema, "minLength"),
         true <- is_binary(value),
         true <- String.length(value) < min do
      errors ++ ["#{path}: shorter than minLength"]
    else
      _ -> errors
    end
  end

  defp check_minimum(errors, value, schema, path) do
    with {:ok, min} <- Map.fetch(schema, "minimum"),
         true <- is_number(value),
         true <- value < min do
      errors ++ ["#{path}: below minimum #{Causalontology.Jcs.encode_number(min)}"]
    else
      _ -> errors
    end
  end

  defp check_maximum(errors, value, schema, path) do
    with {:ok, max} <- Map.fetch(schema, "maximum"),
         true <- is_number(value),
         true <- value > max do
      errors ++ ["#{path}: above maximum #{Causalontology.Jcs.encode_number(max)}"]
    else
      _ -> errors
    end
  end

  defp check_array(errors, value, schema, root, path) when is_list(value) do
    errors =
      case Map.fetch(schema, "minItems") do
        {:ok, min} when length(value) < min ->
          errors ++ ["#{path}: fewer than #{min} items"]

        _ ->
          errors
      end

    case Map.fetch(schema, "items") do
      {:ok, items_schema} ->
        value
        |> Enum.with_index()
        |> Enum.reduce(errors, fn {item, i}, acc ->
          check(item, items_schema, root, "#{path}[#{i}]", acc)
        end)

      :error ->
        errors
    end
  end

  defp check_array(errors, _value, _schema, _root, _path), do: errors

  defp check_object(errors, value, schema, root, path) when is_map(value) do
    props = Map.get(schema, "properties", %{})

    errors =
      Enum.reduce(Map.get(schema, "required", []), errors, fn req, acc ->
        if Map.has_key?(value, req) do
          acc
        else
          acc ++ ["#{path}: required property '#{req}' missing"]
        end
      end)

    errors =
      if Map.get(schema, "additionalProperties") == false do
        Enum.reduce(Map.keys(value), errors, fn key, acc ->
          if Map.has_key?(props, key) do
            acc
          else
            acc ++ ["#{path}: additional property '#{key}'"]
          end
        end)
      else
        errors
      end

    Enum.reduce(props, errors, fn {key, sub}, acc ->
      if Map.has_key?(value, key) do
        check(Map.fetch!(value, key), sub, root, "#{path}.#{key}", acc)
      else
        acc
      end
    end)
  end

  defp check_object(errors, _value, _schema, _root, _path), do: errors

  # Resolve local (#/$defs/...) and cross-file $ref chains to a concrete schema
  # node together with the root document it must be navigated against. A
  # cross-file $ref switches the root to the referenced sibling schema.
  defp deref(%{"$ref" => ref}, root) do
    cond do
      String.starts_with?(ref, "#/") ->
        node = navigate(root, binary_part(ref, 2, byte_size(ref) - 2))
        deref(node, root)

      String.starts_with?(ref, @base) ->
        rest = binary_part(ref, byte_size(@base), byte_size(ref) - byte_size(@base))
        {filename, pointer} = split_ref(rest)
        new_root = load_file(filename)
        node = if pointer == "", do: new_root, else: navigate(new_root, pointer)
        deref(node, new_root)

      true ->
        raise ArgumentError, "unsupported $ref: #{inspect(ref)}"
    end
  end

  defp deref(schema, root), do: {schema, root}

  # Split "<file>.schema.json#/pointer" into {filename, pointer}.
  defp split_ref(rest) do
    case String.split(rest, "#/", parts: 2) do
      [filename, pointer] -> {filename, pointer}
      [filename] -> {filename, ""}
    end
  end

  defp navigate(doc, pointer) do
    pointer
    |> String.split("/")
    |> Enum.reject(&(&1 == ""))
    |> Enum.reduce(doc, fn part, acc -> Map.fetch!(acc, part) end)
  end
end
