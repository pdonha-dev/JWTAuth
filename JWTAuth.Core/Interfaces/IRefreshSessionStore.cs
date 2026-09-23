using JWTAuth.Core.Models;

namespace JWTAuth.Core.Interfaces;

public interface IRefreshSessionStore
{
    Task<RefreshSession> CreateAsync(long userId, CancellationToken cancellationToken = default);
    Task<RefreshRotationResult> RotateAsync(string refreshToken, CancellationToken cancellationToken = default);
    Task<RefreshRevokeResult> RevokeAsync(string refreshToken, CancellationToken cancellationToken = default);
}
