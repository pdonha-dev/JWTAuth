namespace JWTAuth.Core.Models;

public sealed record RefreshSession(
    long UserId,
    string SessionId,
    string RefreshToken,
    DateTimeOffset AbsoluteExpiresAt);

public enum RefreshRotationStatus
{
    Success,
    Invalid,
    Expired,
    Revoked,
    Reused,
    Unavailable
}

public sealed record RefreshRotationResult(
    RefreshRotationStatus Status,
    RefreshSession? Session = null);

public enum RefreshRevokeStatus
{
    Revoked,
    NotFound,
    AlreadyRevoked,
    Expired,
    Unavailable
}

public sealed record RefreshRevokeResult(RefreshRevokeStatus Status);

public sealed class SessionStoreUnavailableException : Exception
{
    public SessionStoreUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
