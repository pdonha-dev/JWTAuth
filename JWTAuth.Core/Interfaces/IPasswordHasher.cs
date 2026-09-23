namespace JWTAuth.Core.Interfaces;

public interface IPasswordHasher
{
    bool IsSupported(string password);
    string HashPassword(string password);
    bool VerifyPassword(string storedHash, string password);
}
