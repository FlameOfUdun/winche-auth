using Microsoft.Extensions.Logging;

namespace Winche.Auth.Logging;

/// <summary>
/// Sign-ins, sign-ups and account changes, logged in the category <see cref="Category"/> as structured entries —
/// <c>Operation</c> (auth.signIn, …), <c>Principal</c> (the uid, or the email tried), <c>Outcome</c> (ok, or the error
/// code) — with a plain sentence. Failures are Warnings; refreshes are Debug (frequent and routine); the rest Information.
/// The Winche console's Logs Explorer shows them as resource <c>auth</c>.
/// </summary>
public static class AuthEvents
{
    public const string Category = "Winche.Auth.Events";

    /// <summary>The meter Winche Auth reports on: <c>winche.auth.events</c>, every logged event by operation and outcome.</summary>
    public const string MeterName = "Winche.Auth";

    private static readonly System.Diagnostics.Metrics.Meter Meter = new(MeterName);

    /// <summary>
    /// Sign-ins, sign-ups, refusals, lockouts, emails and account changes, tagged <c>operation</c> (auth.signIn,
    /// auth.link.google, …) and <c>outcome</c> (ok, invalidCredentials, lockedOut, mfaRequired, …).
    /// </summary>
    private static readonly System.Diagnostics.Metrics.Counter<long> Events =
        Meter.CreateCounter<long>("winche.auth.events", description: "Winche Auth events by operation and outcome");

    internal static void Log(ILogger logger, LogLevel level, string operation, string? principal, string outcome, string message, string? email = null)
    {
        Events.Add(1, new KeyValuePair<string, object?>("operation", operation), new KeyValuePair<string, object?>("outcome", outcome));
        if (!logger.IsEnabled(level)) return;
        logger.Log(level, new EventId(outcome == "ok" ? 1 : 2, "Auth"), new AuthEvent(operation, principal ?? "unknown", outcome, message, email), null,
            static (e, _) => e.Message);
    }

    /// <summary>"INVALID_CREDENTIALS" → "invalidCredentials".</summary>
    internal static string Outcome(string code)
    {
        var parts = code.ToLowerInvariant().Split('_');
        return parts[0] + string.Concat(parts.Skip(1).Select(p => p.Length == 0 ? p : char.ToUpperInvariant(p[0]) + p[1..]));
    }
}

/// <summary>An auth entry: structured values for log stores that keep them, a sentence for those that don't.</summary>
public sealed class AuthEvent(string operation, string principal, string outcome, string message, string? email)
    : IReadOnlyList<KeyValuePair<string, object?>>
{
    public string Operation => operation;
    public string Principal => principal;
    public string Outcome => outcome;
    public string Message => message;

    private KeyValuePair<string, object?>[] Values =>
    [
        new("Operation", operation), new("Principal", principal), new("Outcome", outcome), new("Email", email),
        new("{OriginalFormat}", "{Principal} {Operation}: {Outcome}"),
    ];

    public KeyValuePair<string, object?> this[int index] => Values[index];
    public int Count => 5;
    public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => ((IEnumerable<KeyValuePair<string, object?>>)Values).GetEnumerator();
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    public override string ToString() => message;
}
