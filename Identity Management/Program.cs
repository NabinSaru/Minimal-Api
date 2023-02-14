using Identity_Management;
using Identity_Management.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("manager", pb =>
    {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme)
            .RequireClaim("role", "manager");
    });
});

builder.Services.AddSingleton<Database>();
builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/", () => "Hello World!");

app.MapGet("/register", async (
    string username,
    string password,
    IPasswordHasher<User> hasher,
    Database db,
    HttpContext ctx
    ) =>
{
    var user = new User() { Username = username };

    user.PasswordHash = hasher.HashPassword(user, password);
    await db.PutAsync(user);

    await ctx.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            UserHelper.Convert(user)
            );

    return user;
});

app.MapGet("/login", async (
    string username,
    string password,
    IPasswordHasher<User> hasher,
    Database db,
    HttpContext ctx
    ) =>
{
    var user = await db.GetUserAsync(username);
    var result = hasher.VerifyHashedPassword(user, user.PasswordHash, password);

    if (result == PasswordVerificationResult.Failed)
    {
        return "bad credentials";
    }

    await ctx.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            UserHelper.Convert(user)
            );

    return "logged in";
});

app.MapGet("/promote", async (
    string username,
    Database db
    ) =>
{
    var user = await db.GetUserAsync(username);
    user.Claims.Add(new UserClaim() { Type = "role", Value = "manager" });

    await db.PutAsync(user);

    return "privelege promoted";
});

app.MapGet("/check-privelege", () =>
{
    return "correct!";
}).RequireAuthorization("manager");

app.Run();
