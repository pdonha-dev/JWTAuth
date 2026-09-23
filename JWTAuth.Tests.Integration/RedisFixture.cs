using Testcontainers.Redis;

namespace JWTAuth.Tests.Integration;

public sealed class RedisFixture : IAsyncLifetime
{
    public RedisContainer Container { get; } = new RedisBuilder("redis:7.4.2-alpine")
        .Build();

    public Task InitializeAsync() => Container.StartAsync();
    public Task DisposeAsync() => Container.DisposeAsync().AsTask();
}

[CollectionDefinition(Name)]
public sealed class RedisCollection : ICollectionFixture<RedisFixture>
{
    public const string Name = "redis";
}
