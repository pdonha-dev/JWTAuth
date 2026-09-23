using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using JWTAuth.Core.Interfaces;
using JWTAuth.Core.Models;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace JWTAuth.Core.Services;

public sealed class RedisRefreshSessionStore : IRefreshSessionStore
{
    private const int RefreshTokenBytes = 32;

    private const string CreateScript =
        """
        redis.call('HSET', KEYS[1],
            'userId', ARGV[1],
            'currentHash', ARGV[2],
            'status', 'active',
            'absoluteExpiresAt', ARGV[3])
        redis.call('EXPIRE', KEYS[1], ARGV[4])
        redis.call('SET', KEYS[2], ARGV[5], 'EX', ARGV[4])
        return 1
        """;

    private const string RotateScript =
        """
        local sid = redis.call('GET', KEYS[1])
        if not sid then return {0} end

        local sessionKey = ARGV[1] .. sid
        local status = redis.call('HGET', sessionKey, 'status')
        if not status then return {0} end

        local absolute = tonumber(redis.call('HGET', sessionKey, 'absoluteExpiresAt'))
        local now = tonumber(ARGV[3])
        if not absolute or absolute <= now then
            redis.call('HSET', sessionKey, 'status', 'revoked')
            return {2}
        end

        if status ~= 'active' then return {3} end

        local currentHash = redis.call('HGET', sessionKey, 'currentHash')
        if currentHash ~= ARGV[4] then
            redis.call('HSET', sessionKey, 'status', 'revoked')
            if currentHash then redis.call('DEL', ARGV[2] .. currentHash) end
            return {4}
        end

        local ttl = absolute - now
        local newRefreshKey = ARGV[2] .. ARGV[5]
        redis.call('SET', newRefreshKey, sid, 'EX', ttl)
        redis.call('HSET', sessionKey, 'currentHash', ARGV[5])
        redis.call('EXPIRE', sessionKey, ttl)
        redis.call('EXPIRE', KEYS[1], ttl)

        local userId = redis.call('HGET', sessionKey, 'userId')
        return {1, userId, sid, tostring(absolute)}
        """;

    private const string RevokeScript =
        """
        local sid = redis.call('GET', KEYS[1])
        if not sid then return 0 end

        local sessionKey = ARGV[1] .. sid
        local status = redis.call('HGET', sessionKey, 'status')
        if not status then return 0 end

        local absolute = tonumber(redis.call('HGET', sessionKey, 'absoluteExpiresAt'))
        local now = tonumber(ARGV[3])
        if not absolute or absolute <= now then
            redis.call('HSET', sessionKey, 'status', 'revoked')
            return 3
        end

        if status ~= 'active' then return 2 end

        local currentHash = redis.call('HGET', sessionKey, 'currentHash')
        redis.call('HSET', sessionKey, 'status', 'revoked')
        if currentHash then redis.call('DEL', ARGV[2] .. currentHash) end
        return 1
        """;

    private readonly IDatabase _database;
    private readonly SessionOptions _options;
    private readonly TimeProvider _timeProvider;

    public RedisRefreshSessionStore(
        IConnectionMultiplexer connectionMultiplexer,
        IOptions<SessionOptions> options,
        TimeProvider timeProvider)
    {
        _database = connectionMultiplexer.GetDatabase();
        _options = options.Value;
        _timeProvider = timeProvider;
    }

    public async Task<RefreshSession> CreateAsync(
        long userId,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        DateTimeOffset absoluteExpiresAt = now.AddHours(_options.AbsoluteLifetimeHours);
        long ttlSeconds = Math.Max(1, (long)(absoluteExpiresAt - now).TotalSeconds);
        string sessionId = Guid.NewGuid().ToString("N");
        string refreshToken = CreateOpaqueToken();
        string tokenHash = HashToken(refreshToken);

        try
        {
            await _database.ScriptEvaluateAsync(
                CreateScript,
                [SessionKey(sessionId), RefreshKey(tokenHash)],
                [
                    userId,
                    tokenHash,
                    absoluteExpiresAt.ToUnixTimeSeconds(),
                    ttlSeconds,
                    sessionId
                ]).WaitAsync(cancellationToken);
        }
        catch (RedisException exception)
        {
            throw new SessionStoreUnavailableException("Redis session storage is unavailable.", exception);
        }

        return new RefreshSession(userId, sessionId, refreshToken, absoluteExpiresAt);
    }

    public async Task<RefreshRotationResult> RotateAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        string oldHash = HashToken(refreshToken);
        string newRefreshToken = CreateOpaqueToken();
        string newHash = HashToken(newRefreshToken);

        try
        {
            RedisResult result = await _database.ScriptEvaluateAsync(
                RotateScript,
                [RefreshKey(oldHash)],
                [
                    SessionPrefix,
                    RefreshPrefix,
                    _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
                    oldHash,
                    newHash
                ]).WaitAsync(cancellationToken);

            RedisResult[] values = (RedisResult[]?)result ?? [];
            int status = values.Length > 0 ? (int)values[0] : 0;
            if (status != 1)
            {
                return new RefreshRotationResult(status switch
                {
                    2 => RefreshRotationStatus.Expired,
                    3 => RefreshRotationStatus.Revoked,
                    4 => RefreshRotationStatus.Reused,
                    _ => RefreshRotationStatus.Invalid
                });
            }

            long userId = long.Parse((string)values[1]!, CultureInfo.InvariantCulture);
            string sessionId = (string)values[2]!;
            long absoluteUnix = long.Parse((string)values[3]!, CultureInfo.InvariantCulture);
            var session = new RefreshSession(
                userId,
                sessionId,
                newRefreshToken,
                DateTimeOffset.FromUnixTimeSeconds(absoluteUnix));
            return new RefreshRotationResult(RefreshRotationStatus.Success, session);
        }
        catch (RedisException)
        {
            return new RefreshRotationResult(RefreshRotationStatus.Unavailable);
        }
    }

    public async Task<RefreshRevokeResult> RevokeAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        string tokenHash = HashToken(refreshToken);

        try
        {
            RedisResult result = await _database.ScriptEvaluateAsync(
                RevokeScript,
                [RefreshKey(tokenHash)],
                [SessionPrefix, RefreshPrefix, _timeProvider.GetUtcNow().ToUnixTimeSeconds()])
                .WaitAsync(cancellationToken);

            return new RefreshRevokeResult((int)result switch
            {
                1 => RefreshRevokeStatus.Revoked,
                2 => RefreshRevokeStatus.AlreadyRevoked,
                3 => RefreshRevokeStatus.Expired,
                _ => RefreshRevokeStatus.NotFound
            });
        }
        catch (RedisException)
        {
            return new RefreshRevokeResult(RefreshRevokeStatus.Unavailable);
        }
    }

    private string SessionPrefix => $"{_options.RedisKeyPrefix}session:";
    private string RefreshPrefix => $"{_options.RedisKeyPrefix}refresh:";
    private RedisKey SessionKey(string sessionId) => $"{SessionPrefix}{sessionId}";
    private RedisKey RefreshKey(string hash) => $"{RefreshPrefix}{hash}";

    private static string CreateOpaqueToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(RefreshTokenBytes))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string HashToken(string token)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }
}
