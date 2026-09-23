using System.IdentityModel.Tokens.Jwt;
using System.Text;
using JWTAuth.Core.Models;
using JWTAuth.Core.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuth.Tests.Unit;

public sealed class JwtTokenServiceTests
{
    private static readonly JwtOptions Options = new()
    {
        Issuer = "test-issuer",
        Audience = "test-audience",
        SigningKey = "a-test-signing-key-with-at-least-32-bytes",
        AccessTokenLifetimeSeconds = 60
    };

    [Fact]
    public void Create_ProducesTokenWithExpectedIdentityAndSession()
    {
        var sut = new JwtTokenService(Microsoft.Extensions.Options.Options.Create(Options), TimeProvider.System);

        AccessTokenResult result = sut.Create(new AuthenticatedUser(42, "alice"), "session-1");
        JwtSecurityToken token = new JwtSecurityTokenHandler().ReadJwtToken(result.Value);

        Assert.Equal(Options.Issuer, token.Issuer);
        Assert.Contains(Options.Audience, token.Audiences);
        Assert.Equal("42", token.Subject);
        Assert.Equal("session-1", token.Claims.Single(claim => claim.Type == "sid").Value);
    }

    [Theory]
    [InlineData("wrong-issuer", "test-audience")]
    [InlineData("test-issuer", "wrong-audience")]
    public void Validation_RejectsWrongIssuerOrAudience(string issuer, string audience)
    {
        var sut = new JwtTokenService(Microsoft.Extensions.Options.Options.Create(Options), TimeProvider.System);
        string token = sut.Create(new AuthenticatedUser(42, "alice"), "session-1").Value;
        TokenValidationParameters parameters = ValidationParameters(issuer, audience);

        Assert.ThrowsAny<SecurityTokenValidationException>(() => new JwtSecurityTokenHandler().ValidateToken(token, parameters, out _));
    }

    [Fact]
    public void Validation_RejectsExpiredAndTamperedTokens()
    {
        var past = new FixedTimeProvider(DateTimeOffset.UtcNow.AddMinutes(-10));
        var sut = new JwtTokenService(Microsoft.Extensions.Options.Options.Create(Options), past);
        string expired = sut.Create(new AuthenticatedUser(42, "alice"), "session-1").Value;
        string tampered = expired[..^1] + (expired[^1] == 'a' ? 'b' : 'a');
        var handler = new JwtSecurityTokenHandler();

        Assert.Throws<SecurityTokenExpiredException>(() => handler.ValidateToken(expired, ValidationParameters(Options.Issuer, Options.Audience), out _));
        Assert.ThrowsAny<SecurityTokenValidationException>(() => handler.ValidateToken(tampered, ValidationParameters(Options.Issuer, Options.Audience), out _));
    }

    private static TokenValidationParameters ValidationParameters(string issuer, string audience) => new()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Options.SigningKey)),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
