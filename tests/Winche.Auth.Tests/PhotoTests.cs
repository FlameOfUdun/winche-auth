using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;

namespace Winche.Auth.Tests;

/// <summary>Uploaded photos: kept small, served at an address that can't be guessed, replaced by links and removed.</summary>
[Collection("postgres")]
public class PhotoTests(PostgresFixture pg)
{
    internal static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, (byte)'I', (byte)'H', (byte)'D', (byte)'R', 1, 2, 3];
    internal static readonly byte[] Jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 16, (byte)'J', (byte)'F', (byte)'I', (byte)'F', 0, 1];

    private static async Task<HttpResponseMessage> Upload(TestApp app, string bearer, byte[] bytes, string type = "image/png")
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/me/photo") { Content = new ByteArrayContent(bytes) };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue(type);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await app.Client.SendAsync(req);
    }

    [Fact]
    public async Task A_user_uploads_a_photo_served_at_an_address_of_its_own_and_cached_for_good()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var ann = await app.SignUpAsync("ann@example.com");
        var uploaded = await TestApp.Json(await Upload(app, ann.AccessToken, Png));
        var url = uploaded.GetProperty("photoUrl").GetString()!;
        Assert.Equal("upload", uploaded.GetProperty("photoSource").GetString());
        Assert.Matches(@"/auth/v1/photos/[A-Za-z0-9_-]{24}$", url);

        // Anyone with the address (an <img>), as the image it is, never changing.
        var path = new Uri(url).AbsolutePath;
        var served = await app.Client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal("image/png", served.Content.Headers.ContentType?.MediaType);
        Assert.Equal(Png, await served.Content.ReadAsByteArrayAsync());
        Assert.Equal(TimeSpan.FromDays(1), served.Headers.CacheControl?.MaxAge);   // a removed photo doesn't linger
        Assert.Equal("nosniff", served.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync("/auth/v1/photos/nope")).StatusCode);

        // The type is the image's own (whatever was said), and a new photo has a new address; the old one goes.
        var replaced = await TestApp.Json(await Upload(app, ann.AccessToken, Jpeg, "image/png"));
        var second = new Uri(replaced.GetProperty("photoUrl").GetString()!).AbsolutePath;
        Assert.NotEqual(path, second);
        Assert.Equal("image/jpeg", (await app.Client.GetAsync(second)).Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync(path)).StatusCode);
        // In their next token.
        var next = await app.SessionAsync(await app.PostAsync("/auth/v1/token", new { refreshToken = ann.RefreshToken }));
        Assert.Equal(replaced.GetProperty("photoUrl").GetString(), (await app.WhoAmI(next.AccessToken)).GetProperty("picture").GetString());
    }

    [Fact]
    public async Task Only_small_images_are_kept_and_only_by_their_owner()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var ann = await app.SignUpAsync("ann@example.com");
        Assert.Equal((400, "INVALID_ARGUMENT"), await TestApp.Error(await Upload(app, ann.AccessToken, "<svg onload=alert(1)>"u8.ToArray(), "image/svg+xml")));
        Assert.Equal((400, "invalid-argument"), await TestApp.Error(await Upload(app, ann.AccessToken, [.. Png, .. new byte[WincheAuthLimits.MaxPhotoBytes]])));   // refused unread
        Assert.Equal((400, "invalid-argument"), await TestApp.Error(await Upload(app, ann.AccessToken, [])));
        using var anonymous = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/me/photo") { Content = new ByteArrayContent(Png) };
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.Client.SendAsync(anonymous)).StatusCode);
    }

    [Fact]
    public async Task Removing_it_or_setting_a_link_replaces_the_upload_and_deleting_the_user_takes_it()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var ann = await app.SignUpAsync("ann@example.com");
        var path = new Uri((await TestApp.Json(await Upload(app, ann.AccessToken, Png))).GetProperty("photoUrl").GetString()!).AbsolutePath;
        var removed = await TestApp.Json(await app.SendAsync(HttpMethod.Delete, "/auth/v1/me/photo", ann.AccessToken));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, removed.GetProperty("photoUrl").ValueKind);
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync(path)).StatusCode);

        path = new Uri((await TestApp.Json(await Upload(app, ann.AccessToken, Png))).GetProperty("photoUrl").GetString()!).AbsolutePath;
        var linked = await app.Scoped(a => a.UpdateProfileAsync(ann.Uid, "Ann", "https://cdn.example.com/ann.jpg"));
        Assert.Equal(("https://cdn.example.com/ann.jpg", "link"), (linked.PhotoUrl, linked.PhotoSource));
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync(path)).StatusCode);
        // The same link again (a name change): still a link.
        Assert.Equal("link", (await app.Scoped(a => a.UpdateProfileAsync(ann.Uid, "Ann Smith", "https://cdn.example.com/ann.jpg"))).PhotoSource);

        path = new Uri((await TestApp.Json(await Upload(app, ann.AccessToken, Png))).GetProperty("photoUrl").GetString()!).AbsolutePath;
        await app.Scoped(async a => { await a.DeleteUserAsync(ann.Uid); return true; });
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync(path)).StatusCode);
    }

    [Fact]
    public async Task A_profile_patch_leaves_what_it_doesnt_mention_and_two_uploads_at_once_both_work()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var ann = await app.SignUpAsync("ann@example.com");
        var photo = (await TestApp.Json(await Upload(app, ann.AccessToken, Png))).GetProperty("photoUrl").GetString();
        var renamed = await TestApp.Json(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", ann.AccessToken, new { displayName = "Ann K" }));
        Assert.Equal(("Ann K", photo), (renamed.GetProperty("displayName").GetString(), renamed.GetProperty("photoUrl").GetString()));
        Assert.Equal(HttpStatusCode.OK, (await app.Client.GetAsync(new Uri(photo!).AbsolutePath)).StatusCode);
        // Sent back as it came (a form with both fields): still the upload.
        var same = await TestApp.Json(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", ann.AccessToken, new { displayName = "Ann", photoUrl = photo }));
        Assert.Equal("upload", same.GetProperty("photoSource").GetString());
        // Field names in any case, as before.
        Assert.Equal("Ann Upper", (await TestApp.Json(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", ann.AccessToken, new { DisplayName = "Ann Upper" }))).GetProperty("displayName").GetString());
        await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", ann.AccessToken, new { displayName = "Ann" });
        // An app's cached copy of the upload's address from before the server moved: still the upload.
        var moved = "https://old.example.com/auth/v1/photos/" + photo!.Split('/')[^1];
        Assert.Equal("upload", (await TestApp.Json(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", ann.AccessToken, new { photoUrl = moved }))).GetProperty("photoSource").GetString());
        // An explicit null clears it.
        var cleared = await TestApp.Json(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", ann.AccessToken, new { photoUrl = (string?)null }));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, cleared.GetProperty("photoUrl").ValueKind);
        Assert.Equal("Ann", cleared.GetProperty("displayName").GetString());

        var both = await Task.WhenAll(Upload(app, ann.AccessToken, Png), Upload(app, ann.AccessToken, Jpeg), Upload(app, ann.AccessToken, Png));
        Assert.All(both, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));

        // Anything but text or null for a field is refused (never taken for "clear"); so is a body that isn't an object.
        var photoNow = (await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", ann.AccessToken))).GetProperty("photoUrl").GetString();
        foreach (var bad in new object[] { new { photoUrl = 5 }, new { displayName = new { } }, new[] { 1, 2 }, "text" })
            Assert.Equal(400, (await TestApp.Error(await app.SendAsync(HttpMethod.Patch, "/auth/v1/me", ann.AccessToken, bad))).Item1);
        // A field given twice: refused, not a server error.
        foreach (var body in new[] { """{"displayName":"a","displayName":"b"}""", """{"displayName":"a","DisplayName":"b"}""" })
        {
            using var twice = new HttpRequestMessage(HttpMethod.Patch, "/auth/v1/me") { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
            twice.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ann.AccessToken);
            Assert.Equal(HttpStatusCode.BadRequest, (await app.Client.SendAsync(twice)).StatusCode);
        }
        Assert.Equal(photoNow, (await TestApp.Json(await app.SendAsync(HttpMethod.Get, "/auth/v1/me", ann.AccessToken))).GetProperty("photoUrl").GetString());
    }

    [Fact]
    public async Task An_uploaded_photos_address_follows_the_servers_address()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var ann = await app.SignUpAsync("ann@example.com");
        var id = (await TestApp.Json(await Upload(app, ann.AccessToken, Png))).GetProperty("photoUrl").GetString()!.Split('/')[^1];
        var options = app.Service<WincheAuthOptions>();
        var before = options.Issuer;
        options.Issuer = "https://new.example.com";
        try { Assert.Equal($"https://new.example.com/auth/v1/photos/{id}", (await app.Scoped(a => a.GetUserAsync(ann.Uid)))!.PhotoUrl); }
        finally { options.Issuer = before; }
    }
}
