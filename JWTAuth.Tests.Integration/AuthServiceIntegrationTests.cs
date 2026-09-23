using JWTAuth.Core.Models;
using JWTAuth.Core.Services;
using JWTAuth.Db.Context;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Tests.Integration;

[Collection(PostgreSqlCollection.Name)]
public sealed class AuthServiceIntegrationTests
{
    private readonly PostgreSqlFixture _fixture;

    public AuthServiceIntegrationTests(PostgreSqlFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task RegisterLoginAndDuplicate_UseRelationalBehaviorAndNeverExposePassword()
    {
        await ResetDatabaseAsync();
        await using DataContext context = CreateContext();
        var sut = new AuthService(context, new PasswordHasher());

        RegisterResult registered = await sut.RegisterAsync(" Alice ", "correct horse battery staple");
        RegisterResult duplicate = await sut.RegisterAsync("alice", "another valid password");
        AuthenticatedUser? authenticated = await sut.ValidateCredentialsAsync("ALICE", "correct horse battery staple");
        AuthenticatedUser? rejected = await sut.ValidateCredentialsAsync("alice", "incorrect password");
        string storedHash = await context.Users.Select(user => user.PasswordHash).SingleAsync();

        Assert.Equal(RegisterResult.Success, registered);
        Assert.Equal(RegisterResult.DuplicateUsername, duplicate);
        Assert.Equal("Alice", authenticated?.Username);
        Assert.Null(rejected);
        Assert.NotEqual("correct horse battery staple", storedHash);
        Assert.DoesNotContain(typeof(AuthenticatedUser).GetProperties(), property => property.Name.Contains("Password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ConcurrentRegistration_TranslatesUniqueConstraintViolation()
    {
        await ResetDatabaseAsync();
        await using DataContext firstContext = CreateContext();
        await using DataContext secondContext = CreateContext();
        var first = new AuthService(firstContext, new PasswordHasher());
        var second = new AuthService(secondContext, new PasswordHasher());

        RegisterResult[] results = await Task.WhenAll(
            first.RegisterAsync("same-user", "correct horse battery staple"),
            second.RegisterAsync("SAME-USER", "correct horse battery staple"));

        Assert.Single(results, result => result == RegisterResult.Success);
        Assert.Single(results, result => result == RegisterResult.DuplicateUsername);
    }

    [Fact]
    public async Task Registration_RejectsInvalidUsernamesAndPasswords()
    {
        await ResetDatabaseAsync();
        await using DataContext context = CreateContext();
        var sut = new AuthService(context, new PasswordHasher());

        Assert.Equal(RegisterResult.InvalidUsername, await sut.RegisterAsync("ab", "correct horse battery staple"));
        Assert.Equal(RegisterResult.InvalidUsername, await sut.RegisterAsync("invalid user", "correct horse battery staple"));
        Assert.Equal(RegisterResult.InvalidPassword, await sut.RegisterAsync("valid-user", "too-short"));
        Assert.Equal(RegisterResult.InvalidPassword, await sut.RegisterAsync("valid-user", new string('a', 73)));
        Assert.False(await context.Users.AnyAsync());
    }

    [Fact]
    public async Task FindById_ReturnsOnlyTheAuthenticatedIdentity()
    {
        await ResetDatabaseAsync();
        await using DataContext context = CreateContext();
        var sut = new AuthService(context, new PasswordHasher());
        Assert.Equal(RegisterResult.Success, await sut.RegisterAsync("profile-user", "correct horse battery staple"));
        long userId = await context.Users.Select(user => user.UserId).SingleAsync();

        AuthenticatedUser? user = await sut.FindByIdAsync(userId);

        Assert.Equal(new AuthenticatedUser(userId, "profile-user"), user);
        Assert.Null(await sut.FindByIdAsync(userId + 1));
    }

    private DataContext CreateContext() => new(new DbContextOptionsBuilder<DataContext>()
        .UseNpgsql(_fixture.Container.GetConnectionString())
        .Options);

    private async Task ResetDatabaseAsync()
    {
        await using DataContext context = CreateContext();
        await context.Database.EnsureDeletedAsync();
        await context.Database.MigrateAsync();
    }
}
