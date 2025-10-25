using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Gateway.Config;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
namespace Gateway.Controllers;

[Route("[controller]")]
[ApiController]
public class BffController : Controller
{
    public const string CorsPolicyName = "Bff";
    private readonly Settings _settings;
    private readonly ILogger<BffController> _logger;

    public BffController(IOptions<Settings> options, ILogger<BffController> logger)
    {
        _settings = options.Value;
        _logger = logger;
    }

    [HttpGet("check_session")]
    [EnableCors(CorsPolicyName)]
    public async Task<ActionResult<IDictionary<string, string>>> CheckSessionAsync()
    {
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = result?.Principal ?? User;

        if (principal?.Identity?.IsAuthenticated != true)
        {
            var hintedReturnUrl = Request.Headers["X-ReturnUrl"].FirstOrDefault();
            var redirectTarget = string.IsNullOrWhiteSpace(hintedReturnUrl)
                ? (_settings.RedirectSite ?? "/")
                : hintedReturnUrl;

            var loginUrl = Url.ActionLink(
                action: nameof(Login),
                controller: null,
                values: new { returnUrl = redirectTarget },
                protocol: Request.Scheme,
                host: Request.Host.ToString());

            if (!string.IsNullOrWhiteSpace(loginUrl))
            {
                Response.Headers["X-Login-Url"] = loginUrl;
            }

            return Unauthorized();
        }

        var claims = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var claim in principal.Claims)
        {
            if (claims.TryGetValue(claim.Type, out var existing))
            {
                claims[claim.Type] = $"{existing},{claim.Value}";
                continue;
            }

            claims[claim.Type] = claim.Value;
        }

        return Ok(claims);
    }


    [HttpGet("login")]
    public IActionResult Login([FromQuery] string? returnUrl)
    {
        return Challenge(new AuthenticationProperties { RedirectUri = ResolveRedirectUri(returnUrl) });
    }

    private string ResolveRedirectUri(string? encodedReturnUrl)
    {
        var fallback = _settings.RedirectSite?.Trim();
        if (string.IsNullOrEmpty(fallback))
        {
            return "/";
        }

        if (string.IsNullOrWhiteSpace(encodedReturnUrl))
        {
            return fallback;
        }

        var candidate = DecodeReturnUrl(encodedReturnUrl);
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return fallback;
        }

        if (!Uri.TryCreate(fallback, UriKind.Absolute, out var fallbackUri))
        {
            return fallback;
        }

        if (Uri.TryCreate(candidate, UriKind.Absolute, out var absoluteCandidate))
        {
            return IsSameEndpoint(fallbackUri, absoluteCandidate)
                ? absoluteCandidate.ToString()
                : fallback;
        }

        if (Uri.TryCreate(fallbackUri, candidate, out var resolved))
        {
            return resolved.ToString();
        }

        return fallback;
    }

    private static string DecodeReturnUrl(string encoded)
    {
        try
        {
            var bytes = WebEncoders.Base64UrlDecode(encoded);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (FormatException)
        {
            return Uri.UnescapeDataString(encoded);
        }
        catch (ArgumentException)
        {
            return encoded;
        }
    }

    private static bool IsSameEndpoint(Uri fallback, Uri candidate)
    {
        if (!string.Equals(fallback.Scheme, candidate.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(fallback.Host, candidate.Host, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var fallbackPort = fallback.IsDefaultPort ? GetDefaultPort(fallback.Scheme) : fallback.Port;
        var candidatePort = candidate.IsDefaultPort ? GetDefaultPort(candidate.Scheme) : candidate.Port;

        return fallbackPort == candidatePort;
    }

    private static int GetDefaultPort(string scheme)
    {
        if (string.Equals(scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return 443;
        }

        if (string.Equals(scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return 80;
        }

        return -1;
    }

    [HttpPost("logout")]
    public IActionResult Logout([FromQuery] string? returnUrl)
    {
        var redirectUri = ResolveRedirectUri(returnUrl);
        var properties = new AuthenticationProperties { RedirectUri = redirectUri };

        return SignOut(
            properties,
            CookieAuthenticationDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("status")]
    [EnableCors(CorsPolicyName)]
    public async Task<ActionResult<SessionStatusResponse>> StatusAsync()
    {
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = result?.Principal ?? User;
        var isAuthenticated = principal?.Identity?.IsAuthenticated ?? false;

        var properties = result?.Properties;
        var hasRefreshToken = !string.IsNullOrWhiteSpace(properties?.GetTokenValue("refresh_token"));

        var now = DateTimeOffset.UtcNow;
        double? expiresInSeconds = null;

        if (properties?.ExpiresUtc is { } cookieExpiresUtc)
        {
            var remaining = cookieExpiresUtc - now;
            expiresInSeconds = Math.Max(0, remaining.TotalSeconds);
        }

        var expiresAtValue = properties?.GetTokenValue("expires_at");
        if (!string.IsNullOrWhiteSpace(expiresAtValue) &&
            DateTimeOffset.TryParse(
                expiresAtValue,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var tokenExpiresUtc))
        {
            var tokenRemaining = tokenExpiresUtc - now;
            var tokenSeconds = Math.Max(0, tokenRemaining.TotalSeconds);

            expiresInSeconds = expiresInSeconds.HasValue
                ? Math.Min(expiresInSeconds.Value, tokenSeconds)
                : tokenSeconds;
        }

        return Ok(new SessionStatusResponse(isAuthenticated, hasRefreshToken, expiresInSeconds));
    }
}

public sealed record SessionStatusResponse(bool IsAuthenticated, bool HasRefreshToken, double? ExpiresInSeconds);
