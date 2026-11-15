using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Winche.Auth.Data;

namespace Winche.Auth.Users;

/// <summary>
/// The user manager for Winche Auth's users, with Identity options of its own. ASP.NET Identity's options are one
/// instance for the whole app, so another Identity setup in the same app (the Winche console's admins, the app's own)
/// would otherwise set Winche Auth's password, lockout and email rules, and theirs would get Winche Auth's.
/// </summary>
internal sealed class WincheUserManager(
    IUserStore<WincheUser> store,
    WincheAuthOptions auth,
    IPasswordHasher<WincheUser> passwordHasher,
    IEnumerable<IUserValidator<WincheUser>> userValidators,
    IEnumerable<IPasswordValidator<WincheUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errors,
    IServiceProvider services,
    ILogger<UserManager<WincheUser>> logger)
    : UserManager<WincheUser>(store, Microsoft.Extensions.Options.Options.Create(IdentityOptionsFor(auth)), passwordHasher, userValidators, passwordValidators,
        keyNormalizer, errors, services, logger)
{
    internal static IdentityOptions IdentityOptionsFor(WincheAuthOptions auth)
    {
        var o = new IdentityOptions();
        o.User.RequireUniqueEmail = false;           // anonymous users have none; a unique index guards the rest
        o.User.AllowedUserNameCharacters = null!;    // the user name is the uid
        o.Password.RequiredLength = auth.EmailPasswordSignIn?.MinLength ?? 10;
        o.Password.RequireDigit = false;
        o.Password.RequireLowercase = false;
        o.Password.RequireUppercase = false;
        o.Password.RequireNonAlphanumeric = false;
        o.Password.RequiredUniqueChars = 1;
        o.Lockout.AllowedForNewUsers = true;
        o.Lockout.MaxFailedAccessAttempts = auth.MaxFailedSignIns;
        o.Lockout.DefaultLockoutTimeSpan = auth.LockoutDuration;
        return o;
    }
}
