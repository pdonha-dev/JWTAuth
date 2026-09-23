using Testcontainers.PostgreSql;

namespace JWTAuth.Tests.Integration;

public sealed class PostgreSqlFixture : IAsyncLifetime
{
    public PostgreSqlContainer Container { get; } = new PostgreSqlBuilder("postgres:16.8-alpine")
        .WithDatabase("jwtauth_tests")
        .WithUsername("jwtauth")
        .WithPassword("integration-only-password")
        .Build();

    public Task InitializeAsync() => Container.StartAsync();
    public Task DisposeAsync() => Container.DisposeAsync().AsTask();
}

[CollectionDefinition(Name)]
public sealed class PostgreSqlCollection : ICollectionFixture<PostgreSqlFixture>
{
    public const string Name = "postgresql";
}
