defmodule Causalontology.Schema do
  @moduledoc """
  Schema validation against spec/schema/*.schema.json.

  A deliberately small interpreter for exactly the JSON Schema keywords the
  eight Causalontology schemas use: type, const, enum, pattern, required,
  properties, additionalProperties, items, minItems, minLength, minimum,
  maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
  annotation, as the 2020-12 draft does by default.
  """

  alias Causalontology.{Canonical, Json}

  @schema_files %{
    "causal_relation_object" => "cro.schema.json",
    "occurrent" => "occurrent.schema.json",
    "continuant" => "continuant.schema.json",
    "realizable" => "realizable.schema.json",
    "assertion" => "assertion.schema.json",
    "enrichment" => "enrichment.schema.json",
    "retraction" => "retraction.schema.json",
    "succession" => "succession.schema.json"
  }

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

    schema_dir() |> Path.join(file) |> File.read!() |> Json.parse!()
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
    schema = deref(schema, root)

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
  defp type_ok?(value, "number"), do: is_number(value)
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

  # Follow local $ref chains (#/$defs/...).
  defp deref(%{"$ref" => ref}, root) do
    unless String.starts_with?(ref, "#/") do
      raise ArgumentError, "only local $ref supported: #{inspect(ref)}"
    end

    node =
      ref
      |> binary_part(2, byte_size(ref) - 2)
      |> String.split("/")
      |> Enum.reduce(root, fn part, acc -> Map.fetch!(acc, part) end)

    deref(node, root)
  end

  defp deref(schema, _root), do: schema
end
