defmodule Causalontology.Json do
  @moduledoc """
  A shape-preserving JSON parser (no external dependencies).

  The one property a Causalontology binding needs from its JSON layer is that
  the integer-versus-decimal distinction of the source literal survives to the
  canonicalizer: `1` parses to the Elixir integer `1` and `1.0` parses to the
  Elixir float `1.0`. Elixir integers and floats are distinct types, so a
  hand-written recursive-descent parser that decides the type from the literal
  is all that is required — which is exactly what this module is.

  Values map as: object -> map with binary keys, array -> list,
  string -> binary, number -> integer | float (decided by the literal),
  true/false -> booleans, null -> nil.
  """

  @doc "Parse a complete JSON document; raises ArgumentError on malformed input."
  def parse!(binary) when is_binary(binary) do
    {value, rest} = parse_value(skip_ws(binary))

    case skip_ws(rest) do
      "" -> value
      other -> raise ArgumentError, "trailing data after JSON value: #{peek(other)}"
    end
  end

  # ------------------------------------------------------------------ values

  defp parse_value(<<"{", rest::binary>>), do: parse_object(skip_ws(rest), %{})
  defp parse_value(<<"[", rest::binary>>), do: parse_array(skip_ws(rest), [])
  defp parse_value(<<"\"", rest::binary>>), do: parse_string(rest, [])
  defp parse_value(<<"true", rest::binary>>), do: {true, rest}
  defp parse_value(<<"false", rest::binary>>), do: {false, rest}
  defp parse_value(<<"null", rest::binary>>), do: {nil, rest}

  defp parse_value(<<c, _::binary>> = bin) when c == ?- or c in ?0..?9,
    do: parse_number(bin)

  defp parse_value(bin),
    do: raise(ArgumentError, "unexpected JSON input: #{peek(bin)}")

  # ----------------------------------------------------------------- objects

  defp parse_object(<<"}", rest::binary>>, acc), do: {acc, rest}

  defp parse_object(bin, acc) do
    {key, rest} =
      case bin do
        <<"\"", r::binary>> -> parse_string(r, [])
        _ -> raise ArgumentError, "expected object key: #{peek(bin)}"
      end

    rest =
      case skip_ws(rest) do
        <<":", r::binary>> -> skip_ws(r)
        other -> raise ArgumentError, "expected ':' after object key: #{peek(other)}"
      end

    {value, rest} = parse_value(rest)
    acc = Map.put(acc, key, value)

    case skip_ws(rest) do
      <<",", r::binary>> -> parse_object(skip_ws(r), acc)
      <<"}", r::binary>> -> {acc, r}
      other -> raise ArgumentError, "expected ',' or '}' in object: #{peek(other)}"
    end
  end

  # ------------------------------------------------------------------ arrays

  defp parse_array(<<"]", rest::binary>>, acc), do: {Enum.reverse(acc), rest}

  defp parse_array(bin, acc) do
    {value, rest} = parse_value(bin)

    case skip_ws(rest) do
      <<",", r::binary>> -> parse_array(skip_ws(r), [value | acc])
      <<"]", r::binary>> -> {Enum.reverse([value | acc]), r}
      other -> raise ArgumentError, "expected ',' or ']' in array: #{peek(other)}"
    end
  end

  # ----------------------------------------------------------------- strings

  defp parse_string(<<"\"", rest::binary>>, acc),
    do: {IO.iodata_to_binary(Enum.reverse(acc)), rest}

  defp parse_string(<<"\\", rest::binary>>, acc) do
    {piece, rest} = parse_escape(rest)
    parse_string(rest, [piece | acc])
  end

  defp parse_string(<<c::utf8, rest::binary>>, acc),
    do: parse_string(rest, [<<c::utf8>> | acc])

  defp parse_string(bin, _acc),
    do: raise(ArgumentError, "unterminated string: #{peek(bin)}")

  defp parse_escape(<<"\"", r::binary>>), do: {"\"", r}
  defp parse_escape(<<"\\", r::binary>>), do: {"\\", r}
  defp parse_escape(<<"/", r::binary>>), do: {"/", r}
  defp parse_escape(<<"b", r::binary>>), do: {"\b", r}
  defp parse_escape(<<"f", r::binary>>), do: {"\f", r}
  defp parse_escape(<<"n", r::binary>>), do: {"\n", r}
  defp parse_escape(<<"r", r::binary>>), do: {"\r", r}
  defp parse_escape(<<"t", r::binary>>), do: {"\t", r}

  defp parse_escape(<<"u", hex::binary-size(4), r::binary>>) do
    unit = String.to_integer(hex, 16)

    cond do
      unit in 0xD800..0xDBFF ->
        # A high surrogate must be followed by \u + a low surrogate.
        case r do
          <<"\\u", hex2::binary-size(4), r2::binary>> ->
            unit2 = String.to_integer(hex2, 16)

            if unit2 in 0xDC00..0xDFFF do
              cp = 0x10000 + (unit - 0xD800) * 0x400 + (unit2 - 0xDC00)
              {<<cp::utf8>>, r2}
            else
              raise ArgumentError, "invalid low surrogate in \\u escape"
            end

          _ ->
            raise ArgumentError, "unpaired high surrogate in \\u escape"
        end

      unit in 0xDC00..0xDFFF ->
        raise ArgumentError, "unpaired low surrogate in \\u escape"

      true ->
        {<<unit::utf8>>, r}
    end
  end

  defp parse_escape(bin),
    do: raise(ArgumentError, "invalid escape sequence: #{peek(bin)}")

  # ----------------------------------------------------------------- numbers

  defp parse_number(bin) do
    {literal, rest} = take_number(bin, [])

    if String.contains?(literal, ".") or String.contains?(literal, "e") or
         String.contains?(literal, "E") do
      {to_float(literal), rest}
    else
      {String.to_integer(literal), rest}
    end
  end

  defp take_number(<<c, rest::binary>>, acc)
       when c in ?0..?9 or c == ?- or c == ?+ or c == ?. or c == ?e or c == ?E,
       do: take_number(rest, [c | acc])

  defp take_number(bin, acc), do: {acc |> Enum.reverse() |> List.to_string(), bin}

  # String.to_float/1 requires a fraction part, so normalize forms like
  # "1e-7" to "1.0e-7" before converting; also strip a leading "+" exponent.
  defp to_float(literal) do
    case Regex.run(~r/^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/, literal) do
      [_, sign, int, frac, exp] ->
        build_float(sign, int, frac, exp)

      [_, sign, int, frac] ->
        build_float(sign, int, frac, "")

      [_, sign, int] ->
        build_float(sign, int, "", "")

      nil ->
        raise ArgumentError, "malformed number literal: #{inspect(literal)}"
    end
  end

  defp build_float(sign, int, frac, exp) do
    frac = if frac == "", do: "0", else: frac
    exp = String.trim_leading(exp, "+")
    text = sign <> int <> "." <> frac <> if(exp == "", do: "", else: "e" <> exp)
    String.to_float(text)
  end

  # ------------------------------------------------------------------ helpers

  defp skip_ws(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: skip_ws(rest)
  defp skip_ws(bin), do: bin

  defp peek(bin), do: inspect(binary_part(bin, 0, min(24, byte_size(bin))))
end
