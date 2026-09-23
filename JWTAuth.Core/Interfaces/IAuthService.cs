using JWTAuth.Core.Models;

namespace JWTAuth.Core.Interfaces;

public interface IAuthService
{
    Task<RegisterResult> RegisterAsync(string username, string password, CancellationToken cancellationToken = default);
    Task<AuthenticatedUser?> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default);
    Task<AuthenticatedUser?> FindByIdAsync(long userId, CancellationToken cancellationToken = default);
}
