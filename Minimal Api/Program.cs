using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>("visitor", options => { })
    .AddCookie("local")
    .AddCookie("patreon-cookie")
    .AddOAuth("external-patreon", options =>
    {
        // sets oauth for the external patreon claim identity
        options.SignInScheme = "patreon-cookie";

        // configuration to set the oauth to the mocklab api
        options.ClientId = "id";
        options.ClientSecret = "secret";

        options.AuthorizationEndpoint = "https://oauth.mocklab.io/oauth/authorize";
        options.TokenEndpoint = "https://oauth.mocklab.io/oauth/token";
        options.UserInformationEndpoint = "https://oauth.mocklab.io/userinfo";

        options.CallbackPath = "/cb-patreon";

        options.Scope.Add("profile");
        options.SaveTokens = true;
    });

builder.Services.AddAuthorization(builder =>
{
    // add claim policy 'customer' to any of local, visitor or external patreon
    builder.AddPolicy("customer", policy =>
    {
        policy.AddAuthenticationSchemes("external-patreon", "local", "visitor")
            .RequireAuthenticatedUser();
    });

    // add claim policy 'user' to any of local user
    builder.AddPolicy("user", policy =>
    {
        policy.AddAuthenticationSchemes("local")
            .RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Task.FromResult("welcome to minimal api")).RequireAuthorization("customer");

app.MapGet("/check-auth", ctx =>
    {
        return Task.FromResult("Authorized");
    }
).RequireAuthorization("customer");

app.MapGet("/login-local", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "jen"));
    var identity = new ClaimsIdentity(claims, "cookie");
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("local", user);
});

app.MapGet("/login-patreon", async (HttpContext ctx) =>
{
    await ctx.ChallengeAsync("external-patreon", new AuthenticationProperties()
    {
        RedirectUri = "/"
    });
}).RequireAuthorization("user");

app.Run();

/// <summary>
/// Authentication Handler class for Visitior
/// </summary>
public class VisitorAuthHandler: CookieAuthenticationHandler
{
    /// <summary>
    /// Default constructor for the auth handler
    /// </summary>
    /// <param name="options"> tracks the cookie authentication options </param>
    /// <param name="logger"> handles logging instance </param>
    /// <param name="encoder"> url parser </param>
    /// <param name="clock"> sysyem clock </param>
    public VisitorAuthHandler(
        IOptionsMonitor<CookieAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    /// <summary>
    /// Creates new authentication claim identity and sign in user with the new identites
    /// </summary>
    /// <returns> Authentication Result </returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();

        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>();
        claims.Add(new Claim("usr", "ex"));
        var identiy = new ClaimsIdentity(claims, "visitor");
        var user = new ClaimsPrincipal(identiy);

        await Context.SignInAsync("visitor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "visitor"));
    }
}
