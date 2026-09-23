using System.Data.Common;
using System.Text;
using System.Threading.RateLimiting;
using JWTAuth.Authentication;
using JWTAuth.Core.Interfaces;
using JWTAuth.Core.Models;
using JWTAuth.Core.Services;
using JWTAuth.Db.Context;
using JWTAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using RefreshSessionOptions = JWTAuth.Core.Models.SessionOptions;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

string databaseConnection = builder.Configuration.GetConnectionString("Database")
    ?? throw new InvalidOperationException("ConnectionStrings:Database is required.");
string redisConnection = builder.Configuration.GetConnectionString("Redis")
    ?? throw new InvalidOperationException("ConnectionStrings:Redis is required.");

builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetRequiredSection(JwtOptions.SectionName))
    .ValidateDataAnnotations()
    .Validate(options => Encoding.UTF8.GetByteCount(options.SigningKey) >= 32, "Jwt:SigningKey must contain at least 32 UTF-8 bytes.")
    .ValidateOnStart();
builder.Services.AddOptions<RefreshSessionOptions>()
    .Bind(builder.Configuration.GetRequiredSection(RefreshSessionOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

JwtOptions jwtOptions = builder.Configuration.GetRequiredSection(JwtOptions.SectionName).Get<JwtOptions>()
    ?? throw new InvalidOperationException("Jwt configuration is required.");
if (Encoding.UTF8.GetByteCount(jwtOptions.SigningKey) < 32)
{
    throw new InvalidOperationException("Jwt:SigningKey must contain at least 32 UTF-8 bytes and must be supplied through environment variables or user-secrets.");
}

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddDbContext<DataContext>(options => options.UseNpgsql(databaseConnection));
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
{
    ConfigurationOptions options = ConfigurationOptions.Parse(redisConnection);
    options.AbortOnConnectFail = false;
    return ConnectionMultiplexer.Connect(options);
});
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();
builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
builder.Services.AddSingleton<IRefreshSessionStore, RedisRefreshSessionStore>();
builder.Services.AddSingleton<SessionCsrfService>();

builder.Services.AddControllersWithViews(options => options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "__Host-JWTAuth.Antiforgery";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});
builder.Services.AddProblemDetails();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    options.AddPolicy("register", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 3, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    options.AddPolicy("refresh", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = System.Security.Claims.ClaimTypes.Name
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                StringValues authorization = context.Request.Headers.Authorization;
                if (!StringValues.IsNullOrEmpty(authorization)) return Task.CompletedTask;
                context.Token = context.Request.Cookies[SessionCookieNames.AccessToken];
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                bool hasAuthorizationHeader = !StringValues.IsNullOrEmpty(context.Request.Headers.Authorization);
                bool expectsHtml = context.Request.GetTypedHeaders().Accept?.Any(value => value.MediaType.Value == "text/html") == true;
                if (!hasAuthorizationHeader && expectsHtml)
                {
                    context.HandleResponse();
                    context.Response.Redirect("/Auth/Login");
                }
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();
WebApplication app = builder.Build();
app.UseExceptionHandler();
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.Use(async (context, next) =>
{
    context.Response.Headers.TryAdd("Content-Security-Policy", "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
    context.Response.Headers.TryAdd("Referrer-Policy", "no-referrer");
    context.Response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
    await next();
});
app.UseHttpsRedirection();
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", async (
    DataContext dbContext,
    IConnectionMultiplexer connectionMultiplexer,
    CancellationToken cancellationToken) =>
{
    try
    {
        bool databaseAvailable = await dbContext.Database.CanConnectAsync(cancellationToken);
        await connectionMultiplexer.GetDatabase().PingAsync().WaitAsync(cancellationToken);
        return databaseAvailable
            ? Results.Ok(new { status = "healthy" })
            : Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
    catch (Exception exception) when (exception is DbException or RedisException)
    {
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
}).AllowAnonymous();
app.MapControllerRoute("default", "{controller=Auth}/{action=Login}/{id?}");

await using (AsyncServiceScope scope = app.Services.CreateAsyncScope())
{
    DataContext dbContext = scope.ServiceProvider.GetRequiredService<DataContext>();
    await dbContext.Database.MigrateAsync();
}

await app.RunAsync();

public partial class Program
{
}
