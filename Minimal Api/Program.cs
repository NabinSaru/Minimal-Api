var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/access", (HttpContext ctx) =>
{
    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    var authPayload = authCookie.Split("=").Last();
    var payload = authCookie.Split(":");
    var key = payload[0];
    var value = payload[1];
    return value;
});

app.MapGet("/login", (HttpContext ctx) =>
{
    ctx.Response.Headers["set-cookie"] = "auth=usr: john";
    return "Ok";
});

app.Run();
