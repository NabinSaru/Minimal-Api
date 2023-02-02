using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();

var app = builder.Build();

app.Use((ctx, next) =>
{
    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("auth-cookie");

    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    var protectedPayload = authCookie.Split("=").Last();
    var decryptedPayload = protector.Unprotect(protectedPayload);
    var payload = decryptedPayload.Split(":");
    var key = payload[0];
    var value = payload[1];

    // similar to name, age
    var claims = new List<Claim>();
    claims.Add(new Claim(key, value));

    // identity equivalent to passport and claim maybe password id
    var identity = new ClaimsIdentity(claims);
    // claims principal is the authority like license accessing driving authority
    ctx.User = new ClaimsPrincipal(identity);

    return next();
});

app.MapGet("/", () => {
    return "welcome to minimal api";
});

app.MapGet("/access", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr").Value;
});

app.MapGet("/login", (AuthService auth) =>
{
    auth.SignIn();
    return "Ok";
});

app.Run();

public class AuthService
{
    private readonly IDataProtectionProvider _idp;
    private readonly IHttpContextAccessor _accessor;

    public AuthService(IDataProtectionProvider idp, IHttpContextAccessor accessor)
    {
        _idp = idp;
        _accessor = accessor;
    }

    public void SignIn()
    {
        var protector = _idp.CreateProtector("auth-cookie");
        _accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr: john")}";
    }
}
