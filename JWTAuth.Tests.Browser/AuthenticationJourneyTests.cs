using System.Text.Json;
using Microsoft.Playwright;

namespace JWTAuth.Tests.Browser;

public sealed class AuthenticationJourneyTests
{
    [Fact]
    public async Task RegisterLoginProfileExpireRefreshProfileLogout()
    {
        string baseUrl = Environment.GetEnvironmentVariable("E2E_BASE_URL")
            ?? throw new InvalidOperationException("E2E_BASE_URL is required; start the Docker Compose stack before browser tests.");
        string username = $"browser-{Guid.NewGuid():N}";
        const string password = "correct horse battery staple";

        using IPlaywright playwright = await Playwright.CreateAsync();
        await using IBrowser browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
        await using IBrowserContext context = await browser.NewContextAsync(new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        IPage page = await context.NewPageAsync();

        IResponse? registrationPage = await page.GotoAsync($"{baseUrl}/Auth/Register");
        Assert.Contains("default-src 'self'", registrationPage?.Headers["content-security-policy"]);
        await page.Locator("input[name=Username]").FillAsync(username);
        await page.Locator("input[name=Password]").FillAsync(password);
        await page.Locator("form button[type=submit]").ClickAsync();

        await page.Locator("input[name=Username]").FillAsync(username);
        await page.Locator("input[name=Password]").FillAsync(password);
        await page.Locator("form button[type=submit]").ClickAsync();
        await page.WaitForURLAsync("**/Auth/Profile");
        await ExpectTextAsync(page, username);

        IReadOnlyList<BrowserContextCookiesResult> cookies = await context.CookiesAsync();
        BrowserContextCookiesResult accessCookie = cookies.Single(cookie => cookie.Name == "AccessToken");
        Assert.All(
            cookies.Where(cookie => cookie.Name is "AccessToken" or "RefreshToken" or "SessionCsrf"),
            cookie =>
            {
                Assert.True(cookie.HttpOnly);
                Assert.True(cookie.Secure);
                Assert.Equal(SameSiteAttribute.Strict, cookie.SameSite);
            });

        await page.SetExtraHTTPHeadersAsync(new Dictionary<string, string> { ["Authorization"] = "Bearer invalid-token" });
        IResponse? invalidBearerResponse = await page.GotoAsync($"{baseUrl}/Auth/Profile");
        Assert.Equal(401, invalidBearerResponse?.Status);
        await page.SetExtraHTTPHeadersAsync(new Dictionary<string, string>());
        await page.GotoAsync($"{baseUrl}/Auth/Profile");
        await ExpectTextAsync(page, username);

        DateTimeOffset expiresAt = ReadExpiration(accessCookie.Value);
        TimeSpan untilExpired = expiresAt - DateTimeOffset.UtcNow + TimeSpan.FromSeconds(1);
        if (untilExpired > TimeSpan.Zero) await Task.Delay(untilExpired);

        await page.GotoAsync($"{baseUrl}/Auth/Profile");
        await page.WaitForURLAsync("**/Auth/Login");
        await page.GotoAsync($"{baseUrl}/Auth/Renew");
        await page.Locator("form button[type=submit]").ClickAsync();
        await page.WaitForURLAsync("**/Auth/Profile");
        await ExpectTextAsync(page, username);

        await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Sair" }).ClickAsync();
        await page.WaitForURLAsync("**/Auth/Login?logout=revoked");
        Assert.DoesNotContain(await context.CookiesAsync(), cookie => cookie.Name is "AccessToken" or "RefreshToken");
        await page.GotoAsync($"{baseUrl}/Auth/Profile");
        await page.WaitForURLAsync("**/Auth/Login");
    }

    private static async Task ExpectTextAsync(IPage page, string text)
    {
        await page.GetByText(text, new PageGetByTextOptions { Exact = true }).WaitForAsync();
    }

    private static DateTimeOffset ReadExpiration(string jwt)
    {
        string payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + ((4 - payload.Length % 4) % 4), '=');
        using JsonDocument document = JsonDocument.Parse(Convert.FromBase64String(payload));
        return DateTimeOffset.FromUnixTimeSeconds(document.RootElement.GetProperty("exp").GetInt64());
    }
}
