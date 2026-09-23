using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Core.Models;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required]
    public string Issuer { get; init; } = string.Empty;

    [Required]
    public string Audience { get; init; } = string.Empty;

    [Required]
    [MinLength(32)]
    public string SigningKey { get; init; } = string.Empty;

    [Range(5, 3600)]
    public int AccessTokenLifetimeSeconds { get; init; } = 300;
}
