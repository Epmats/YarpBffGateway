using System;
using System.Globalization;
using System.Threading.Tasks;
using Duende.AccessTokenManagement;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Gateway.Services;

public class TokenRefreshService : ITokenRefreshService
{
    private readonly IUserTokenManagementService _userTokenManagementService;
    private readonly ILogger<TokenRefreshService> _logger;

    public TokenRefreshService(
        IUserTokenManagementService userTokenManagementService,
        ILogger<TokenRefreshService> logger)
    {
        _userTokenManagementService = userTokenManagementService;
        _logger = logger;
    }

    public async Task<string?> RefreshTokenAsync(HttpContext httpContext)
    {
        var authResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (authResult?.Properties == null || authResult.Principal == null)
        {
            _logger.LogWarning("Cannot refresh token for unauthenticated user.");
            return null;
        }

        try
        {
            var userToken = await _userTokenManagementService.GetUserAccessTokenAsync(
                httpContext.User,
                new UserTokenRequestParameters { ForceRenewal = true });

            if (userToken == null || !string.IsNullOrWhiteSpace(userToken.Error))
            {
                _logger.LogError("Error refreshing token: {Error}", userToken?.Error ?? "Unknown error");
                await SignOutAsync(httpContext);
                return null;
            }

            var properties = authResult.Properties;
            var tokensUpdated = false;

            var storedAccessToken = properties.GetTokenValue("access_token");
            if (!string.Equals(storedAccessToken, userToken.AccessToken, StringComparison.Ordinal))
            {
                properties.UpdateTokenValue("access_token", userToken.AccessToken);
                tokensUpdated = true;
            }

            if (!string.IsNullOrWhiteSpace(userToken.RefreshToken))
            {
                var storedRefreshToken = properties.GetTokenValue("refresh_token");
                if (!string.Equals(storedRefreshToken, userToken.RefreshToken, StringComparison.Ordinal))
                {
                    properties.UpdateTokenValue("refresh_token", userToken.RefreshToken);
                    tokensUpdated = true;
                }
            }

            if (userToken.Expiration.HasValue)
            {
                properties.UpdateTokenValue("expires_at", userToken.Expiration.Value.ToString("o", CultureInfo.InvariantCulture));
                tokensUpdated = true;
            }

            if (tokensUpdated)
            {
                await httpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    authResult.Principal,
                    properties);
            }

            return userToken.AccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An exception occurred while refreshing the token.");
            await SignOutAsync(httpContext);
            return null;
        }
    }

    private static async Task SignOutAsync(HttpContext httpContext)
    {
        await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await httpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
    }
}
