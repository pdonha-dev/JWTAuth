using JWTAuth.Core.Models;
using JWTAuth.Core.Services;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace JWTAuth.Tests.Integration;

[Collection(RedisCollection.Name)]
public sealed class RedisRefreshSessionStoreIntegrationTests
{
    private readonly RedisFixture _fixture;

    public RedisRefreshSessionStoreIntegrationTests(RedisFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Rotation_IsAtomicAndReusingPreviousTokenRevokesTheSession()
    {
        await using ConnectionMultiplexer redis = await ConnectAndFlushAsync();
        var store = CreateStore(redis);
        RefreshSession original = await store.CreateAsync(10);

        RefreshRotationResult rotated = await store.RotateAsync(original.RefreshToken);
        RefreshRotationResult reused = await store.RotateAsync(original.RefreshToken);
        RefreshRotationResult successor = await store.RotateAsync(rotated.Session!.RefreshToken);

        Assert.Equal(RefreshRotationStatus.Success, rotated.Status);
        Assert.Equal(RefreshRotationStatus.Reused, reused.Status);
        Assert.Equal(RefreshRotationStatus.Invalid, successor.Status);
    }

    [Fact]
    public async Task ConcurrentRotation_AllowsOneWinnerThenRevokesItsSuccessor()
    {
        await using ConnectionMultiplexer redis = await ConnectAndFlushAsync();
        var store = CreateStore(redis);
        RefreshSession original = await store.CreateAsync(20);

        RefreshRotationResult[] results = await Task.WhenAll(
            store.RotateAsync(original.RefreshToken),
            store.RotateAsync(original.RefreshToken));

        Assert.Single(results, result => result.Status == RefreshRotationStatus.Success);
        Assert.Single(results, result => result.Status == RefreshRotationStatus.Reused);
        RefreshSession winner = results.Single(result => result.Status == RefreshRotationStatus.Success).Session!;
        Assert.NotEqual(RefreshRotationStatus.Success, (await store.RotateAsync(winner.RefreshToken)).Status);
    }

    [Fact]
    public async Task LostRotationResponse_RetryRevokesTheIssuedSuccessor()
    {
        await using ConnectionMultiplexer redis = await ConnectAndFlushAsync();
        var store = CreateStore(redis);
        RefreshSession original = await store.CreateAsync(30);
        RefreshRotationResult responseThatClientLost = await store.RotateAsync(original.RefreshToken);

        Assert.Equal(RefreshRotationStatus.Reused, (await store.RotateAsync(original.RefreshToken)).Status);
        Assert.NotEqual(RefreshRotationStatus.Success, (await store.RotateAsync(responseThatClientLost.Session!.RefreshToken)).Status);
    }

    [Fact]
    public async Task SessionsForSameUser_AreIndependent()
    {
        await using ConnectionMultiplexer redis = await ConnectAndFlushAsync();
        var store = CreateStore(redis);
        RefreshSession first = await store.CreateAsync(40);
        RefreshSession second = await store.CreateAsync(40);

        Assert.Equal(RefreshRevokeStatus.Revoked, (await store.RevokeAsync(first.RefreshToken)).Status);
        Assert.Equal(RefreshRotationStatus.Success, (await store.RotateAsync(second.RefreshToken)).Status);
    }

    [Fact]
    public async Task LogoutConcurrentWithRefresh_LeavesNoUsableSession()
    {
        await using ConnectionMultiplexer redis = await ConnectAndFlushAsync();
        var store = CreateStore(redis);
        RefreshSession original = await store.CreateAsync(50);

        Task<RefreshRotationResult> rotationTask = store.RotateAsync(original.RefreshToken);
        Task<RefreshRevokeResult> revokeTask = store.RevokeAsync(original.RefreshToken);
        await Task.WhenAll(rotationTask, revokeTask);
        RefreshRotationResult rotation = await rotationTask;

        if (rotation.Session is not null)
        {
            Assert.NotEqual(RefreshRotationStatus.Success, (await store.RotateAsync(rotation.Session.RefreshToken)).Status);
        }
        Assert.NotEqual(RefreshRotationStatus.Success, (await store.RotateAsync(original.RefreshToken)).Status);
    }

    [Fact]
    public async Task AbsoluteExpiration_IsNotExtendedByRotation()
    {
        await using ConnectionMultiplexer redis = await ConnectAndFlushAsync();
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var store = CreateStore(redis, clock, 1);
        RefreshSession original = await store.CreateAsync(60);
        clock.Advance(TimeSpan.FromMinutes(30));
        RefreshRotationResult rotated = await store.RotateAsync(original.RefreshToken);
        clock.Advance(TimeSpan.FromMinutes(31));

        Assert.Equal(original.AbsoluteExpiresAt, rotated.Session?.AbsoluteExpiresAt);
        Assert.Equal(RefreshRotationStatus.Expired, (await store.RotateAsync(rotated.Session!.RefreshToken)).Status);
    }

    private async Task<ConnectionMultiplexer> ConnectAndFlushAsync()
    {
        ConnectionMultiplexer connection = await ConnectionMultiplexer.ConnectAsync(_fixture.Container.GetConnectionString());
        await connection.GetDatabase().ExecuteAsync("FLUSHDB");
        return connection;
    }

    private static RedisRefreshSessionStore CreateStore(ConnectionMultiplexer redis, TimeProvider? timeProvider = null, int lifetimeHours = 24)
    {
        return new RedisRefreshSessionStore(
            redis,
            Microsoft.Extensions.Options.Options.Create(new SessionOptions { AbsoluteLifetimeHours = lifetimeHours, RedisKeyPrefix = $"test:{Guid.NewGuid():N}:" }),
            timeProvider ?? TimeProvider.System);
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan value) => now = now.Add(value);
    }
}
