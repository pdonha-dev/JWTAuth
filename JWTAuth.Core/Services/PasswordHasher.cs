using System.Text;
using JWTAuth.Core.Interfaces;

namespace JWTAuth.Core.Services;

public sealed class PasswordHasher : IPasswordHasher
{
    private const int BcryptMaximumBytes = 72;
    private const int WorkFactor = 12;

    public static string DummyHash { get; } = BCrypt.Net.BCrypt.HashPassword(
        "dummy-password-never-used",
        WorkFactor);

    public bool IsSupported(string password)
    {
        return Encoding.UTF8.GetByteCount(password) <= BcryptMaximumBytes;
    }

    public string HashPassword(string password)
    {
        if (!IsSupported(password))
        {
            throw new ArgumentException("Password exceeds BCrypt's 72-byte input limit.", nameof(password));
        }

        return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
    }

    public bool VerifyPassword(string storedHash, string password)
    {
        if (!IsSupported(password))
        {
            return false;
        }

        try
        {
            return BCrypt.Net.BCrypt.Verify(password, storedHash);
        }
        catch (Exception exception) when (exception is ArgumentException or BCrypt.Net.SaltParseException)
        {
            return false;
        }
    }
}
