using System.Text;
using JWTAuth.Core.Services;

namespace JWTAuth.Tests.Unit;

public sealed class PasswordHasherTests
{
    [Fact]
    public void HashPassword_StoresHashAndVerifiesPassword()
    {
        var sut = new PasswordHasher();
        const string password = "correct horse battery staple";

        string hash = sut.HashPassword(password);

        Assert.NotEqual(password, hash);
        Assert.StartsWith("$2", hash);
        Assert.True(sut.VerifyPassword(hash, password));
        Assert.False(sut.VerifyPassword(hash, "incorrect password"));
    }

    [Fact]
    public void IsSupported_UsesBcryptUtf8ByteLimit()
    {
        var sut = new PasswordHasher();
        string seventyTwoBytes = new('a', 72);
        string seventyThreeBytes = seventyTwoBytes + "a";
        string multibyteOverLimit = string.Concat(Enumerable.Repeat("á", 37));

        Assert.Equal(72, Encoding.UTF8.GetByteCount(seventyTwoBytes));
        Assert.True(sut.IsSupported(seventyTwoBytes));
        Assert.False(sut.IsSupported(seventyThreeBytes));
        Assert.False(sut.IsSupported(multibyteOverLimit));
        Assert.Throws<ArgumentException>(() => sut.HashPassword(seventyThreeBytes));
    }

    [Fact]
    public void VerifyPassword_RejectsUnsupportedInputAndMalformedHashes()
    {
        var sut = new PasswordHasher();

        Assert.False(sut.VerifyPassword("not-a-bcrypt-hash", "valid password"));
        Assert.False(sut.VerifyPassword(PasswordHasher.DummyHash, new string('a', 73)));
    }
}
