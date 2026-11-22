using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Winche.Auth.Data;

namespace Winche.Auth.Users;

/// <summary>Uploaded photos: small images Winche Auth keeps and serves, so an app needs no storage of its own for them.</summary>
internal sealed partial class WincheAuthService
{
    public Task<WincheUserInfo> SetPhotoAsync(string uid, byte[] image, CancellationToken ct)
    {
        var type = PhotoType(image) ?? throw new AuthException(AuthErrorCodes.InvalidArgument, "A photo is a JPEG, PNG or WebP image.");
        if (image.Length > WincheAuthLimits.MaxPhotoBytes)
            throw new AuthException(AuthErrorCodes.InvalidArgument, $"A photo is at most {WincheAuthLimits.MaxPhotoBytes / 1024} KB: shrink it first (256 × 256 is plenty).");
        return InTransaction(async () =>
        {
            var user = await Find(uid);
            var id = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');
            // One row per user, written in one statement: two uploads at once take turns (the last wins), never fail.
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO auth_user_photos ("UserId", "PhotoId", "ContentType", "Bytes", "UpdatedAt")
                VALUES ({uid}, {id}, {type}, {image}, {time.GetUtcNow()})
                ON CONFLICT ("UserId") DO UPDATE SET "PhotoId" = EXCLUDED."PhotoId", "ContentType" = EXCLUDED."ContentType",
                    "Bytes" = EXCLUDED."Bytes", "UpdatedAt" = EXCLUDED."UpdatedAt"
                """, ct);
            user.PhotoUrl = options.PhotoAddress(id);
            user.PhotoSource = "upload";
            await Save(user);
            var info = await InfoAsync(user);
            await Record(WincheAuthUserEvent.Updated, info, ct);
            return info;
        }, ct);
    }

    public Task<WincheUserInfo> RemovePhotoAsync(string uid, CancellationToken ct) => InTransaction(async () =>
    {
        var user = await Find(uid);
        var changed = await db.Photos.Where(p => p.UserId == uid).ExecuteDeleteAsync(ct) > 0;
        if (user.PhotoSource == "upload")
        {
            user.PhotoUrl = null;
            user.PhotoSource = null;   // a provider's picture comes back at the next sign-in with it
            await Save(user);
            changed = true;
        }
        var info = await InfoAsync(user);
        if (changed) await Record(WincheAuthUserEvent.Updated, info, ct);
        return info;
    }, ct);

    public async Task<UserPhoto?> GetPhotoAsync(string photoId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(photoId) || photoId.Length > 40) return null;
        return await db.Photos.AsNoTracking().Where(p => p.PhotoId == photoId)
            .Select(p => new UserPhoto(p.Bytes, p.ContentType, p.UpdatedAt)).FirstOrDefaultAsync(ct);
    }

    /// <summary>The image's type from its first bytes (never from what the uploader says): JPEG, PNG or WebP, else null.</summary>
    internal static string? PhotoType(ReadOnlySpan<byte> b) =>
        b.Length >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF ? "image/jpeg"
        : b.Length >= 8 && b[..8].SequenceEqual((ReadOnlySpan<byte>)[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) ? "image/png"
        : b.Length >= 12 && b[..4].SequenceEqual("RIFF"u8) && b[8..12].SequenceEqual("WEBP"u8) ? "image/webp"
        : null;

    /// <summary>
    /// A provider being unlinked: its picture, if it's the user's photo, goes with it (another provider's, at its next
    /// sign-in, can take its place).
    /// </summary>
    private static void ForgetProviderPhoto(WincheUser user, string provider)
    {
        if (user.PhotoSource != $"provider:{provider}") return;
        user.PhotoUrl = null;
        user.PhotoSource = null;
    }

    /// <summary>
    /// A provider's picture on sign-in: kept while the photo is that provider's (refreshed) or there's none; an upload or a
    /// link set by the app or an admin stays.
    /// </summary>
    private static void TakeProviderPhoto(WincheUser user, string provider, string? picture)
    {
        if (PhotoOrNull(picture) is not { } url) return;
        var source = $"provider:{provider}";
        if (user.PhotoSource == source || (user.PhotoUrl is null && user.PhotoSource is null))
        {
            user.PhotoUrl = url;
            user.PhotoSource = source;
        }
    }
}
