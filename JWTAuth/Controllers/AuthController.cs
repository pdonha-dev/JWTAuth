using System.Security.Claims;
using JWTAuth.Authentication;
using JWTAuth.Core.Interfaces;
using JWTAuth.Core.Models;
using JWTAuth.Models;
using JWTAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace JWTAuth.Controllers;

[ResponseCache(Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class AuthController : Controller
{
    private readonly IAuthService _authService;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IRefreshSessionStore _sessionStore;
    private readonly SessionCsrfService _csrfService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, IJwtTokenService jwtTokenService, IRefreshSessionStore sessionStore, SessionCsrfService csrfService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _jwtTokenService = jwtTokenService;
        _sessionStore = sessionStore;
        _csrfService = csrfService;
        _logger = logger;
    }

    [HttpGet, AllowAnonymous]
    public IActionResult Login(string? logout = null)
    {
        ViewBag.StatusMessage = logout switch
        {
            "revoked" => "Sessão encerrada e refresh token revogado.",
            "local-only" => "Cookies removidos, mas não foi possível confirmar a revogação no Redis.",
            _ => null
        };
        return View(new Login());
    }

    [HttpPost, AllowAnonymous, EnableRateLimiting("login")]
    public async Task<IActionResult> Login(Login input, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return View(input);
        AuthenticatedUser? user = await _authService.ValidateCredentialsAsync(input.Username, input.Password, cancellationToken);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Usuário ou senha inválidos.");
            return View(input);
        }

        try
        {
            RefreshSession session = await _sessionStore.CreateAsync(user.UserId, cancellationToken);
            WriteSessionCookies(_jwtTokenService.Create(user, session.SessionId), session, _csrfService.CreateToken());
            return RedirectToAction(nameof(Profile));
        }
        catch (SessionStoreUnavailableException exception)
        {
            _logger.LogError(exception, "Session creation failed because Redis is unavailable");
            ModelState.AddModelError(string.Empty, "Não foi possível iniciar a sessão. Tente novamente.");
            return View(input);
        }
    }

    [HttpGet, AllowAnonymous]
    public IActionResult Register() => View(new RegisterUser());

    [HttpPost, AllowAnonymous, EnableRateLimiting("register")]
    public async Task<IActionResult> Register(RegisterUser input, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return View(input);
        RegisterResult result = await _authService.RegisterAsync(input.Username, input.Password, cancellationToken);
        if (result == RegisterResult.Success) return RedirectToAction(nameof(Login));
        ModelState.AddModelError(string.Empty, result switch
        {
            RegisterResult.DuplicateUsername => "Nome de usuário indisponível.",
            RegisterResult.InvalidPassword => "A senha deve ter entre 12 caracteres e 72 bytes em UTF-8.",
            _ => "Nome de usuário inválido."
        });
        return View(input);
    }

    [HttpGet, Authorize]
    public async Task<IActionResult> Profile(CancellationToken cancellationToken)
    {
        if (!long.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out long userId)) return Challenge();
        AuthenticatedUser? user = await _authService.FindByIdAsync(userId, cancellationToken);
        if (user is null) return Challenge();
        ViewBag.SessionCsrf = Request.Cookies[SessionCookieNames.CsrfToken];
        return View(user);
    }

    [HttpGet, AllowAnonymous]
    public IActionResult Renew()
    {
        string? csrfToken = Request.Cookies[SessionCookieNames.CsrfToken];
        if (string.IsNullOrEmpty(csrfToken) || !Request.Cookies.ContainsKey(SessionCookieNames.RefreshToken)) return RedirectToAction(nameof(Login));
        return View(new SessionActionInput { CsrfToken = csrfToken });
    }

    [HttpPost, AllowAnonymous, IgnoreAntiforgeryToken, EnableRateLimiting("refresh")]
    public async Task<IActionResult> Refresh(SessionActionInput input, CancellationToken cancellationToken)
    {
        if (!IsValidSessionCsrf(input) || !Request.Cookies.TryGetValue(SessionCookieNames.RefreshToken, out string? refreshToken))
        {
            ClearSessionCookies();
            return Unauthorized();
        }
        RefreshRotationResult rotation = await _sessionStore.RotateAsync(refreshToken, cancellationToken);
        if (rotation.Status == RefreshRotationStatus.Unavailable)
        {
            ViewBag.StatusMessage = "O serviço de sessão está temporariamente indisponível. Tente novamente.";
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return View("Renew", input);
        }
        if (rotation.Status != RefreshRotationStatus.Success || rotation.Session is null)
        {
            ClearSessionCookies();
            return RedirectToAction(nameof(Login));
        }
        AuthenticatedUser? user = await _authService.FindByIdAsync(rotation.Session.UserId, cancellationToken);
        if (user is null)
        {
            await _sessionStore.RevokeAsync(rotation.Session.RefreshToken, cancellationToken);
            ClearSessionCookies();
            return RedirectToAction(nameof(Login));
        }
        WriteSessionCookies(_jwtTokenService.Create(user, rotation.Session.SessionId), rotation.Session, input.CsrfToken);
        return RedirectToAction(nameof(Profile));
    }

    [HttpPost, AllowAnonymous, IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout(SessionActionInput input, CancellationToken cancellationToken)
    {
        if (!IsValidSessionCsrf(input) || !Request.Cookies.TryGetValue(SessionCookieNames.RefreshToken, out string? refreshToken))
        {
            ClearSessionCookies();
            return RedirectToAction(nameof(Login));
        }
        RefreshRevokeResult revokeResult = await _sessionStore.RevokeAsync(refreshToken, cancellationToken);
        ClearSessionCookies();
        string result = revokeResult.Status is RefreshRevokeStatus.Revoked
            or RefreshRevokeStatus.AlreadyRevoked
            or RefreshRevokeStatus.Expired
                ? "revoked"
                : "local-only";
        return RedirectToAction(nameof(Login), new { logout = result });
    }

    private bool IsValidSessionCsrf(SessionActionInput input) => _csrfService.IsValid(Request.Cookies[SessionCookieNames.CsrfToken], input.CsrfToken);

    private void WriteSessionCookies(AccessTokenResult accessToken, RefreshSession session, string csrfToken)
    {
        Response.Cookies.Append(SessionCookieNames.AccessToken, accessToken.Value, BuildCookieOptions("/", accessToken.ExpiresAt));
        Response.Cookies.Append(SessionCookieNames.RefreshToken, session.RefreshToken, BuildCookieOptions("/Auth", session.AbsoluteExpiresAt));
        Response.Cookies.Append(SessionCookieNames.CsrfToken, csrfToken, BuildCookieOptions("/Auth", session.AbsoluteExpiresAt));
    }

    private static CookieOptions BuildCookieOptions(string path, DateTimeOffset expiresAt) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = path,
        Expires = expiresAt,
        IsEssential = true
    };

    private void ClearSessionCookies()
    {
        Response.Cookies.Delete(SessionCookieNames.AccessToken, BuildDeleteOptions("/"));
        Response.Cookies.Delete(SessionCookieNames.RefreshToken, BuildDeleteOptions("/Auth"));
        Response.Cookies.Delete(SessionCookieNames.CsrfToken, BuildDeleteOptions("/Auth"));
    }

    private static CookieOptions BuildDeleteOptions(string path) => new() { Secure = true, SameSite = SameSiteMode.Strict, Path = path };
}
