using System.Security.Cryptography;
using System.Text;

namespace JWTAuth.Services;

public sealed class SessionCsrfService
{
    public string CreateToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public bool IsValid(string? cookieToken, string? submittedToken)
    {
        if (string.IsNullOrEmpty(cookieToken) || string.IsNullOrEmpty(submittedToken))
        {
            return false;
        }

        byte[] expected = Encoding.UTF8.GetBytes(cookieToken);
        byte[] actual = Encoding.UTF8.GetBytes(submittedToken);
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
