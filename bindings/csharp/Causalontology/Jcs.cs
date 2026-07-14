// RFC 8785 (JSON Canonicalization Scheme) serialization.
//
// Keys sorted by UTF-16 code units (String.CompareOrdinal), minimal
// string escaping with lowercase \u00xx for controls, and ECMAScript-style
// canonical numbers mirroring the Python binding's _jcs_number:
// integers verbatim; an integral double below 1e21 printed as an integer
// (via BigInteger, so 5e20 prints all its digits); everything else as the
// shortest round-trip decimal with the ES6 exponent form (e-7, not e-07).

using System.Globalization;
using System.Numerics;
using System.Text;

namespace Causalontology;

public static class Jcs
{
    /// <summary>The RFC 8785 canonical JSON text of a parsed JSON value.</summary>
    public static string Serialize(object? value)
    {
        var sb = new StringBuilder();
        Write(value, sb);
        return sb.ToString();
    }

    private static void Write(object? value, StringBuilder sb)
    {
        switch (value)
        {
            case null:
                sb.Append("null");
                break;
            case bool b:
                sb.Append(b ? "true" : "false");
                break;
            case long l:
                sb.Append(l.ToString(CultureInfo.InvariantCulture));
                break;
            case int i:
                sb.Append(i.ToString(CultureInfo.InvariantCulture));
                break;
            case double d:
                sb.Append(NumberToString(d));
                break;
            case string s:
                WriteString(s, sb);
                break;
            case List<object?> list:
                sb.Append('[');
                for (var idx = 0; idx < list.Count; idx++)
                {
                    if (idx > 0)
                        sb.Append(',');
                    Write(list[idx], sb);
                }
                sb.Append(']');
                break;
            case JsonMap map:
                sb.Append('{');
                var keys = map.Keys.ToList();
                keys.Sort(string.CompareOrdinal); // UTF-16 code-unit order
                for (var idx = 0; idx < keys.Count; idx++)
                {
                    if (idx > 0)
                        sb.Append(',');
                    WriteString(keys[idx], sb);
                    sb.Append(':');
                    Write(map[keys[idx]], sb);
                }
                sb.Append('}');
                break;
            default:
                throw new ArgumentException(
                    $"cannot canonicalize {value.GetType()}");
        }
    }

    private static void WriteString(string s, StringBuilder sb)
    {
        sb.Append('"');
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\f': sb.Append("\\f"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (ch < 0x20)
                        sb.Append("\\u").Append(
                            ((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    else
                        sb.Append(ch);
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>The canonical decimal form of a double (mirrors Python _jcs_number).</summary>
    public static string NumberToString(double n)
    {
        if (double.IsNaN(n) || double.IsInfinity(n))
            throw new ArgumentException(
                "NaN and Infinity are not permitted (RFC 8785)");
        if (n == 0)
            return "0"; // covers -0.0 as well
        if (n == Math.Floor(n) && Math.Abs(n) < 1e21)
            return new BigInteger(n).ToString(CultureInfo.InvariantCulture);
        // shortest round-trip decimal ("R" is shortest-round-trip on .NET Core 3.0+)
        var r = n.ToString("R", CultureInfo.InvariantCulture);
        var ei = r.IndexOfAny(new[] { 'e', 'E' });
        if (ei >= 0)
        {
            // normalize the exponent the way ES6 does: 1E-07 -> 1e-7, keep e+NN
            var mantissa = r[..ei];
            var exponent = r[(ei + 1)..];
            var sign = exponent.StartsWith('-') ? "-" : "+";
            var digits = exponent.TrimStart('+', '-').TrimStart('0');
            if (digits.Length == 0)
                digits = "0";
            r = mantissa + "e" + sign + digits;
        }
        return r;
    }
}
