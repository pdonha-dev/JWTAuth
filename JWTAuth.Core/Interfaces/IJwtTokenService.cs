using JWTAuth.Core.Models;

namespace JWTAuth.Core.Interfaces;

public interface IJwtTokenService
{
    AccessTokenResult Create(AuthenticatedUser user, string sessionId);
}
