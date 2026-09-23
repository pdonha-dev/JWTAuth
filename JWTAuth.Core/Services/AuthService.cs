using JWTAuth.Core.Interfaces;
using JWTAuth.Core.Models;
using JWTAuth.Db.Context;
using JWTAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Core.Services;

public sealed class AuthService : IAuthService
{
    public const int UsernameMaxLength = 64;
    public const int UsernameMinLength = 3;
    public const int PasswordMinLength = 12;

    private readonly DataContext _dbContext;
    private readonly IPasswordHasher _passwordHasher;

    public AuthService(DataContext dbContext, IPasswordHasher passwordHasher)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
    }

    public async Task<RegisterResult> RegisterAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        string displayUsername = username.Trim();
        if (!IsValidUsername(displayUsername))
        {
            return RegisterResult.InvalidUsername;
        }

        if (password.Length < PasswordMinLength || !_passwordHasher.IsSupported(password))
        {
            return RegisterResult.InvalidPassword;
        }

        string normalizedUsername = NormalizeUsername(displayUsername);
        if (await _dbContext.Users.AnyAsync(
                user => user.NormalizedUsername == normalizedUsername,
                cancellationToken))
        {
            return RegisterResult.DuplicateUsername;
        }

        var user = new User
        {
            Username = displayUsername,
            NormalizedUsername = normalizedUsername,
            PasswordHash = _passwordHasher.HashPassword(password)
        };

        _dbContext.Users.Add(user);

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
            return RegisterResult.Success;
        }
        catch (DbUpdateException)
        {
            _dbContext.Entry(user).State = EntityState.Detached;
            if (await _dbContext.Users.AnyAsync(
                    existing => existing.NormalizedUsername == normalizedUsername,
                    cancellationToken))
            {
                return RegisterResult.DuplicateUsername;
            }

            throw;
        }
    }

    public async Task<AuthenticatedUser?> ValidateCredentialsAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        string displayUsername = username.Trim();
        if (!IsValidUsername(displayUsername))
        {
            _passwordHasher.VerifyPassword(PasswordHasher.DummyHash, password);
            return null;
        }

        string normalizedUsername = NormalizeUsername(displayUsername);
        User? user = await _dbContext.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(
                candidate => candidate.NormalizedUsername == normalizedUsername,
                cancellationToken);

        string hash = user?.PasswordHash ?? PasswordHasher.DummyHash;
        bool validPassword = _passwordHasher.VerifyPassword(hash, password);

        return user is not null && validPassword
            ? new AuthenticatedUser(user.UserId, user.Username)
            : null;
    }

    public async Task<AuthenticatedUser?> FindByIdAsync(
        long userId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.Users
            .AsNoTracking()
            .Where(user => user.UserId == userId)
            .Select(user => new AuthenticatedUser(user.UserId, user.Username))
            .SingleOrDefaultAsync(cancellationToken);
    }

    private static string NormalizeUsername(string username) => username.Trim().ToUpperInvariant();

    private static bool IsValidUsername(string username)
    {
        return username.Length is >= UsernameMinLength and <= UsernameMaxLength
            && username.All(character =>
                character is >= 'a' and <= 'z'
                    or >= 'A' and <= 'Z'
                    or >= '0' and <= '9'
                    or '.'
                    or '_'
                    or '-');
    }
}
