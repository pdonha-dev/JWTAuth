using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Core.Models;

public sealed class SessionOptions
{
    public const string SectionName = "Session";

    [Range(1, 720)]
    public int AbsoluteLifetimeHours { get; init; } = 168;

    [Required]
    public string RedisKeyPrefix { get; init; } = "jwtauth:";
}
