using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>("visitor", options => {})
    .AddCookie("local");

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("customer", policy =>
    {
        policy.AddAuthenticationSchemes("local", "visitor")
            .RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Task.FromResult("welcome to minimal api"));

app.MapGet("/access", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr").Value;
});

app.MapGet("/login-local", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "jen"));
    var identity = new ClaimsIdentity(claims, "cookie");
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("cookie", user);
});

app.Run();

public class VisitorAuthHandler: CookieAuthenticationHandler
{
    public VisitorAuthHandler(
        IOptionsMonitor<CookieAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();

        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>();
        claims.Add(new Claim("usr", "jen"));
        var identiy = new ClaimsIdentity(claims, "visitor");
        var user = new ClaimsPrincipal(identiy);

        await Context.SignInAsync("visitor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "visitor"));
    }
}
