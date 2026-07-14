defmodule Causalontology.Jcs do
  @moduledoc """
  RFC 8785 (JSON Canonicalization Scheme) serialization.

  Mirrors `bindings/python/causalontology/canonical.py`'s `_jcs` exactly:
  sorted keys (code-point order, which equals UTF-16 code-unit order for the
  ASCII keys the standard uses), minimal string escaping with lowercase
  `\\u00xx` for control characters, and ECMAScript-style canonical numbers
  (`1.0` -> `1`, `0.7` stays `0.7`, exponent forms normalized to `e-7` /
  `e+21`). Full ECMAScript exponent formatting for extreme magnitudes is
  pinned at the 1.0.0 conformance freeze, exactly as in the Python binding.
  """

  @doc "The canonical RFC 8785 serialization of a JSON value, as a binary."
  def encode(nil), do: "null"
  def encode(true), do: "true"
  def encode(false), do: "false"
  def encode(n) when is_number(n), do: encode_number(n)
  def encode(s) when is_binary(s), do: encode_string(s)

  def encode(list) when is_list(list),
    do: "[" <> Enum.map_join(list, ",", &encode/1) <> "]"

  def encode(map) when is_map(map) do
    pairs =
      map
      |> Map.to_list()
      # Sort keys by code points, mirroring the Python reference's
      # sorted(..., key=[ord(c) for c in key]) — identical for ASCII keys.
      |> Enum.sort_by(fn {k, _v} -> String.to_charlist(k) end)

    "{" <>
      Enum.map_join(pairs, ",", fn {k, v} -> encode_string(k) <> ":" <> encode(v) end) <>
      "}"
  end

  def encode(other), do: raise(ArgumentError, "cannot canonicalize #{inspect(other)}")

  # ----------------------------------------------------------------- strings

  @doc "A JSON string with RFC 8785 minimal escaping."
  def encode_string(s) when is_binary(s) do
    inner = s |> String.to_charlist() |> Enum.map(&escape_char/1)
    IO.iodata_to_binary([?", inner, ?"])
  end

  defp escape_char(?"), do: "\\\""
  defp escape_char(?\\), do: "\\\\"
  defp escape_char(8), do: "\\b"
  defp escape_char(9), do: "\\t"
  defp escape_char(10), do: "\\n"
  defp escape_char(12), do: "\\f"
  defp escape_char(13), do: "\\r"

  defp escape_char(c) when c < 0x20 do
    # Lowercase four-digit hex, mirroring Python's "\\u%04x".
    hex = c |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0")
    "\\u" <> hex
  end

  defp escape_char(c), do: <<c::utf8>>

  # ----------------------------------------------------------------- numbers

  @doc "ECMAScript-style canonical number serialization (RFC 8785)."
  def encode_number(n) when is_integer(n), do: Integer.to_string(n)

  def encode_number(n) when is_float(n) do
    # NaN and Infinity cannot arise: Elixir floats are always finite and our
    # own JSON parser only produces finite literals, so no isfinite gate is
    # needed here (the Python reference raises on them defensively).
    cond do
      n == 0.0 ->
        "0"

      trunc(n) == n and abs(n) < 1.0e21 ->
        # An integral float below 1e21 serializes as an integer (1.0 -> "1").
        Integer.to_string(trunc(n))

      true ->
        shortest(n)
    end
  end

  # The shortest round-trip decimal (Ryu via OTP's :short option), with the
  # exponent form normalized to ECMAScript style: mantissa without a
  # trailing ".0", exponent as e-7 (not e-07) or e+21.
  defp shortest(n) do
    text = :erlang.float_to_binary(n, [:short])

    case String.split(text, "e") do
      [_plain] -> text
      [mantissa, exponent] -> normalize_exponent(mantissa, exponent)
    end
  end

  defp normalize_exponent(mantissa, exponent) do
    mantissa =
      if String.ends_with?(mantissa, ".0") do
        binary_part(mantissa, 0, byte_size(mantissa) - 2)
      else
        mantissa
      end

    {sign, digits} =
      case exponent do
        "-" <> d -> {"-", d}
        "+" <> d -> {"+", d}
        d -> {"+", d}
      end

    digits =
      case String.trim_leading(digits, "0") do
        "" -> "0"
        d -> d
      end

    mantissa <> "e" <> sign <> digits
  end
end
