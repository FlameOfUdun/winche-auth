using System.Net;
using System.Net.Http.Headers;

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
        Assert.Contains("immutable", served.Headers.CacheControl?.ToString());
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
}
