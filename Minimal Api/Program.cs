using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;

const string AuthSchema = "cookie";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddCookie(AuthSchema);

var app = builder.Build();

app.UseAuthentication();

app.Use((ctx, next) =>
{
    // bypass authorization for login purpose
    if (ctx.Request.Path.StartsWithSegments("/login"))
    {
        return next();
    }

    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
    {
        ctx.Response.StatusCode = 401;
        return Task.CompletedTask;

    }
    if (!ctx.User.HasClaim("role", "admin"))
    {
        ctx.Response.StatusCode = 403;
        return Task.CompletedTask;
    }

    return next();
});

app.MapGet("/", () => {
    return "welcome to minimal api";
});

app.MapGet("/access", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
});

app.MapGet("/isAdmin", (HttpContext ctx) =>
{
    return true;
});

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "john"));
    claims.Add(new Claim("role", "admin"));
    var identity = new ClaimsIdentity(claims, "cookie");
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("cookie", user);
    return "Ok";
});

app.Run();

