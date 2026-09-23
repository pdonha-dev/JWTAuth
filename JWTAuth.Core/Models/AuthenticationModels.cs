namespace JWTAuth.Core.Models;

public enum RegisterResult
{
    Success,
    DuplicateUsername,
    InvalidUsername,
    InvalidPassword
}

public sealed record AuthenticatedUser(long UserId, string Username);

public sealed record AccessTokenResult(string Value, DateTimeOffset ExpiresAt);
