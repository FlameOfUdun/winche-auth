using System.Security.Cryptography;
using System.Text;

namespace Winche.Auth.Mfa;

/// <summary>Time-based one-time codes (RFC 6238: HMAC-SHA1, 6 digits, 30-second steps), as authenticator apps make them.</summary>
internal static class Totp
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>A new 160-bit secret, base32 as authenticator apps take it.</summary>
    public static string NewSecret() => Base32(RandomNumberGenerator.GetBytes(20));

    public static long Step(DateTimeOffset now) => now.ToUnixTimeSeconds() / 30;

    /// <summary>
    /// The step <paramref name="code"/> belongs to — the current one or either neighbour, for clocks a little off — or
    /// null. Steps at or before <paramref name="lastUsed"/> don't count, so a code works once.
    /// </summary>
    public static long? Match(string secret, string? code, DateTimeOffset now, long lastUsed)
    {
        code = new string((code ?? "").Where(char.IsAsciiDigit).ToArray());
        if (code.Length != 6) return null;
        var key = FromBase32(secret);
        var current = Step(now);
        for (var step = current - 1; step <= current + 1; step++)
        {
            if (step <= lastUsed) continue;
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(key, step)), Encoding.ASCII.GetBytes(code))) return step;
        }
        return null;
    }

    public static string Code(byte[] key, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, step);
        var hash = HMACSHA1.HashData(key, counter);
        var offset = hash[^1] & 0x0F;
        var value = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (value % 1_000_000).ToString("D6");
    }

    /// <summary>The <c>otpauth://</c> address an authenticator app reads from a QR code.</summary>
    public static string Uri(string issuer, string account, string secret) =>
        $"otpauth://totp/{System.Uri.EscapeDataString(issuer)}:{System.Uri.EscapeDataString(account)}" +
        $"?secret={secret}&issuer={System.Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";

    public static string Base32(byte[] data)
    {
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] FromBase32(string text)
    {
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in text.ToUpperInvariant().Where(c => c != '=' && c != ' '))
        {
            var v = Alphabet.IndexOf(c);
            if (v < 0) throw new FormatException("Not base32.");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        return [.. bytes];
    }
}
