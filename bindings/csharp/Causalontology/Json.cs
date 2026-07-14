// A lossless JSON layer for the Causalontology C# binding.
//
// JSON values are represented as plain CLR values:
//   null, bool, long (integer literals), double (decimal literals),
//   string, List<object?> (arrays), and JsonMap (objects).
//
// The integer-versus-decimal source distinction (1 versus 1.0) survives
// to the canonicalizer: a literal with no '.', 'e', or 'E' becomes a
// long; anything else becomes a double. JsonMap keeps an explicit key
// insertion-order list - we deliberately do not rely on Dictionary's
// de-facto ordering.

using System.Globalization;
using System.Text;

namespace Causalontology;

/// <summary>A JSON object preserving key insertion order.</summary>
public sealed class JsonMap : IEnumerable<KeyValuePair<string, object?>>
{
    private readonly List<string> _order = new();
    private readonly Dictionary<string, object?> _values = new();

    public int Count => _order.Count;

    /// <summary>The keys in insertion order.</summary>
    public IReadOnlyList<string> Keys => _order;

    public object? this[string key]
    {
        get => _values[key];
        set
        {
            if (!_values.ContainsKey(key))
                _order.Add(key);
            _values[key] = value;
        }
    }

    /// <summary>Collection-initializer support: new JsonMap { { "k", v } }.</summary>
    public void Add(string key, object? value) => this[key] = value;

    public bool ContainsKey(string key) => _values.ContainsKey(key);

    public bool TryGetValue(string key, out object? value)
        => _values.TryGetValue(key, out value);

    /// <summary>Python dict.get(): the value, or null when absent.</summary>
    public object? Get(string key)
        => _values.TryGetValue(key, out var v) ? v : null;

    /// <summary>Python dict.get(key, default) for string values.</summary>
    public string? GetString(string key) => Get(key) as string;

    public bool Remove(string key)
    {
        if (!_values.Remove(key))
            return false;
        _order.Remove(key);
        return true;
    }

    /// <summary>Python dict.setdefault().</summary>
    public void SetDefault(string key, object? value)
    {
        if (!_values.ContainsKey(key))
            this[key] = value;
    }

    /// <summary>A shallow copy (Python dict(record)).</summary>
    public JsonMap Copy()
    {
        var copy = new JsonMap();
        foreach (var key in _order)
            copy[key] = _values[key];
        return copy;
    }

    public IEnumerator<KeyValuePair<string, object?>> GetEnumerator()
    {
        foreach (var key in _order)
            yield return new KeyValuePair<string, object?>(key, _values[key]);
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        => GetEnumerator();
}

/// <summary>A small lossless recursive-descent JSON parser.</summary>
public static class Json
{
    /// <summary>Parse a JSON document; integers stay long, decimals stay double.</summary>
    public static object? Parse(string text)
    {
        var pos = 0;
        var value = ParseValue(text, ref pos);
        SkipWhitespace(text, ref pos);
        if (pos != text.Length)
            throw new FormatException($"trailing data at position {pos}");
        return value;
    }

    /// <summary>Parse a JSON file.</summary>
    public static object? ParseFile(string path) => Parse(File.ReadAllText(path));

    /// <summary>Deep JSON equality; longs and doubles compare numerically (Python 1 == 1.0).</summary>
    public static bool DeepEquals(object? a, object? b)
    {
        if (a is null || b is null)
            return a is null && b is null;
        if (a is bool ba)
            return b is bool bb && ba == bb;
        if (IsNumber(a) && IsNumber(b))
            return ToDouble(a) == ToDouble(b);
        if (a is string sa)
            return b is string sb && sa == sb;
        if (a is List<object?> la)
        {
            if (b is not List<object?> lb || la.Count != lb.Count)
                return false;
            for (var i = 0; i < la.Count; i++)
                if (!DeepEquals(la[i], lb[i]))
                    return false;
            return true;
        }
        if (a is JsonMap ma)
        {
            if (b is not JsonMap mb || ma.Count != mb.Count)
                return false;
            foreach (var (key, value) in ma)
            {
                if (!mb.TryGetValue(key, out var other) || !DeepEquals(value, other))
                    return false;
            }
            return true;
        }
        return a.Equals(b);
    }

    /// <summary>True when the value is a JSON number (long, double, or int).</summary>
    public static bool IsNumber(object? value) => value is long or double or int;

    /// <summary>A JSON number as a double, for comparisons.</summary>
    public static double ToDouble(object? value) => value switch
    {
        long l => l,
        int i => i,
        double d => d,
        _ => throw new InvalidCastException($"not a number: {value}"),
    };

    private static void SkipWhitespace(string text, ref int pos)
    {
        while (pos < text.Length && text[pos] is ' ' or '\t' or '\n' or '\r')
            pos++;
    }

    private static object? ParseValue(string text, ref int pos)
    {
        SkipWhitespace(text, ref pos);
        if (pos >= text.Length)
            throw new FormatException("unexpected end of JSON");
        var ch = text[pos];
        switch (ch)
        {
            case '{': return ParseObject(text, ref pos);
            case '[': return ParseArray(text, ref pos);
            case '"': return ParseString(text, ref pos);
            case 't': Expect(text, ref pos, "true"); return true;
            case 'f': Expect(text, ref pos, "false"); return false;
            case 'n': Expect(text, ref pos, "null"); return null;
            default: return ParseNumber(text, ref pos);
        }
    }

    private static void Expect(string text, ref int pos, string literal)
    {
        if (pos + literal.Length > text.Length
            || text.Substring(pos, literal.Length) != literal)
            throw new FormatException($"invalid literal at position {pos}");
        pos += literal.Length;
    }

    private static JsonMap ParseObject(string text, ref int pos)
    {
        pos++; // consume '{'
        var map = new JsonMap();
        SkipWhitespace(text, ref pos);
        if (pos < text.Length && text[pos] == '}')
        {
            pos++;
            return map;
        }
        while (true)
        {
            SkipWhitespace(text, ref pos);
            var key = ParseString(text, ref pos);
            SkipWhitespace(text, ref pos);
            if (pos >= text.Length || text[pos] != ':')
                throw new FormatException($"expected ':' at position {pos}");
            pos++;
            map[key] = ParseValue(text, ref pos);
            SkipWhitespace(text, ref pos);
            if (pos >= text.Length)
                throw new FormatException("unterminated object");
            if (text[pos] == ',') { pos++; continue; }
            if (text[pos] == '}') { pos++; return map; }
            throw new FormatException($"expected ',' or '}}' at position {pos}");
        }
    }

    private static List<object?> ParseArray(string text, ref int pos)
    {
        pos++; // consume '['
        var list = new List<object?>();
        SkipWhitespace(text, ref pos);
        if (pos < text.Length && text[pos] == ']')
        {
            pos++;
            return list;
        }
        while (true)
        {
            list.Add(ParseValue(text, ref pos));
            SkipWhitespace(text, ref pos);
            if (pos >= text.Length)
                throw new FormatException("unterminated array");
            if (text[pos] == ',') { pos++; continue; }
            if (text[pos] == ']') { pos++; return list; }
            throw new FormatException($"expected ',' or ']' at position {pos}");
        }
    }

    private static string ParseString(string text, ref int pos)
    {
        if (text[pos] != '"')
            throw new FormatException($"expected string at position {pos}");
        pos++;
        var sb = new StringBuilder();
        while (true)
        {
            if (pos >= text.Length)
                throw new FormatException("unterminated string");
            var ch = text[pos++];
            if (ch == '"')
                return sb.ToString();
            if (ch != '\\')
            {
                sb.Append(ch);
                continue;
            }
            if (pos >= text.Length)
                throw new FormatException("unterminated escape");
            var esc = text[pos++];
            switch (esc)
            {
                case '"': sb.Append('"'); break;
                case '\\': sb.Append('\\'); break;
                case '/': sb.Append('/'); break;
                case 'b': sb.Append('\b'); break;
                case 'f': sb.Append('\f'); break;
                case 'n': sb.Append('\n'); break;
                case 'r': sb.Append('\r'); break;
                case 't': sb.Append('\t'); break;
                case 'u':
                    if (pos + 4 > text.Length)
                        throw new FormatException("truncated \\u escape");
                    sb.Append((char)ushort.Parse(
                        text.Substring(pos, 4), NumberStyles.HexNumber,
                        CultureInfo.InvariantCulture));
                    pos += 4;
                    break;
                default:
                    throw new FormatException($"invalid escape '\\{esc}'");
            }
        }
    }

    private static object ParseNumber(string text, ref int pos)
    {
        var start = pos;
        if (pos < text.Length && text[pos] == '-')
            pos++;
        while (pos < text.Length
               && (char.IsAsciiDigit(text[pos])
                   || text[pos] is '.' or 'e' or 'E' or '+' or '-'))
            pos++;
        var literal = text[start..pos];
        if (literal.Length == 0)
            throw new FormatException($"invalid number at position {start}");
        // the literal decides: no '.', 'e', or 'E' means an integer (long)
        if (!literal.Contains('.') && !literal.Contains('e') && !literal.Contains('E'))
            return long.Parse(literal, CultureInfo.InvariantCulture);
        return double.Parse(literal, CultureInfo.InvariantCulture);
    }
}
