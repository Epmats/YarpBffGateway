using System.Collections.Generic;
using System.Globalization;
using System.Net.Http.Headers;
using Gateway.Controllers;
using Microsoft.AspNetCore.Authentication;
using Yarp.ReverseProxy.Transforms;
using Gateway.Config;
using Gateway.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Duende.AccessTokenManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Duende.AccessTokenManagement.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var cookieLifetime = TimeSpan.FromHours(12);

ConfigureTenantConfiguration(builder);

builder.Services.AddControllers();

var configuration = builder.Configuration;

builder.Services.Configure<Settings>(
    builder.Configuration.GetSection("BffSettings"));
builder.Services.Configure<OpenIdConnect>(
    builder.Configuration.GetSection("OpenIdConnect"));

builder
    .Services.AddAuthorization()
    .AddAuthentication(options => {
        configuration.Bind("Authentication", options);
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(o =>
    {
        o.Cookie.SameSite = SameSiteMode.None;
        o.Cookie.Name = ".Gateway.Auth";
        o.ExpireTimeSpan = cookieLifetime;
        o.SlidingExpiration = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Events.OnSigningIn = context =>
        {
            var now = DateTimeOffset.UtcNow;
            context.Properties.IsPersistent = true;
            context.Properties.AllowRefresh = true;
            context.Properties.IssuedUtc = now;
            context.Properties.ExpiresUtc = now.Add(cookieLifetime);
            return Task.CompletedTask;
        };
        o.Events.OnRedirectToLogin = context =>
        {
            if (IsApiRequest(context.Request))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers["X-Login-Url"] = context.RedirectUri;
                return Task.CompletedTask;
            }

            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };
        o.Events.OnSigningOut = async e => { await e.HttpContext.RevokeRefreshTokenAsync(); };
    })
    .AddOpenIdConnect(options =>
    {
        configuration.Bind("OpenIdConnect", options);

        options.Events.OnTicketReceived = context =>
        {
            var now = DateTimeOffset.UtcNow;
            var properties = context.Properties ?? new AuthenticationProperties();
            properties.IsPersistent = true;
            properties.AllowRefresh = true;
            properties.IssuedUtc = now;
            properties.ExpiresUtc = now.Add(cookieLifetime);
            context.Properties = properties;
            return Task.CompletedTask;
        };
    });

builder.Services.AddOpenIdConnectAccessTokenManagement();

builder.Services.AddUserAccessTokenHttpClient("apiClient", configureClient: client =>
{
    var setting = builder.Configuration.GetSection("BffSettings")["RedirectSite"];
    client.BaseAddress = new Uri(setting!);
});

builder.Services.AddHttpClient("oidc");            // enkel HttpClient för discovery/refresh
builder.Services.AddHttpContextAccessor();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddScoped<ITokenRefreshService, TokenRefreshService>();

builder.Services.AddCors(options =>
    options.AddPolicy(
        BffController.CorsPolicyName,
        policyBuilder =>
        {
            var allowedOrigins = configuration.GetSection("CorsSettings:AllowedOrigins").Get<string[]>();

            policyBuilder
                .WithOrigins(allowedOrigins ?? Array.Empty<string>())
                .AllowAnyMethod()
                .AllowCredentials()
                .AllowAnyHeader();
        }
    )
);

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(builderContext =>
    {
        if (string.Equals(builderContext.Route.AuthorizationPolicy, "default", StringComparison.OrdinalIgnoreCase))
        {
            builderContext.AddRequestTransform(async transformContext =>
            {
                var httpContext = transformContext.HttpContext;
                if (httpContext?.User?.Identity?.IsAuthenticated != true)
                {
                    return;
                }

                var authResult =
                    await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                var properties = authResult?.Properties;

                var openIdOptions = httpContext.RequestServices
                    .GetRequiredService<IOptions<OpenIdConnect>>();

                var tokenLocation = openIdOptions.Value.BearerTokenLocation;

                var expiresAtValue = properties?.GetTokenValue("expires_at");
                string? accessToken = null;

                if (!string.IsNullOrWhiteSpace(expiresAtValue) &&
                    DateTimeOffset.TryParse(
                        expiresAtValue,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out var expiresAtUtc) &&
                    expiresAtUtc <= DateTimeOffset.UtcNow)
                {
                    var tokenRefreshService = httpContext.RequestServices.GetRequiredService<ITokenRefreshService>();
                    accessToken = await tokenRefreshService.RefreshTokenAsync(httpContext);
                }
                else
                {
                    accessToken = await httpContext.GetUserAccessTokenAsync();
                }

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    await SignOutAsync(httpContext);
                    return;
                }

                var refreshToken = properties?.GetTokenValue("refresh_token");

                string tokenToForward = accessToken;

                if (!string.IsNullOrWhiteSpace(tokenLocation) &&
                    !string.Equals(tokenLocation, "access_token", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.Equals(tokenLocation, "refresh_token", StringComparison.OrdinalIgnoreCase))
                    {
                        tokenToForward = refreshToken ?? tokenToForward;
                    }
                    else
                    {
                        var fromProperties = properties?.GetTokenValue(tokenLocation);
                        if (!string.IsNullOrWhiteSpace(fromProperties))
                        {
                            tokenToForward = fromProperties;
                        }
                    }
                }

                if (string.IsNullOrWhiteSpace(tokenToForward))
                {
                    await SignOutAsync(httpContext);
                    return;
                }

                transformContext.ProxyRequest.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", tokenToForward);
            });
        }
    });

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();

app.UseCors(BffController.CorsPolicyName);

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapGet("/healthz", () => Results.Ok("OK"))
       .AllowAnonymous(); // bypass auth if you have it
}


app.MapControllerRoute(name: "default", pattern: "{controller}/{action=Index}/{id?}");

// Add YARP middleware to handle reverse proxying
app.MapReverseProxy();

app.Run();

static void ConfigureTenantConfiguration(WebApplicationBuilder builder)
{
    var environment = builder.Environment;
    var configuration = builder.Configuration;

    var tenant =
        Environment.GetEnvironmentVariable("GATEWAY_TENANT") ??
        configuration["Gateway:Tenant"] ??
        configuration["Tenant"];

    if (string.IsNullOrWhiteSpace(tenant))
    {
        return;
    }

    tenant = tenant.Trim();

    var tenantPrefix = tenant.ToLowerInvariant();
    var envName = environment.EnvironmentName ?? string.Empty;

    var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        $"{tenantPrefix}.appsettings.json"
    };

    if (!string.IsNullOrWhiteSpace(envName))
    {
        candidates.Add($"{tenantPrefix}.appsettings.{envName}.json");
        candidates.Add($"{tenantPrefix}.appsettings.{envName.ToUpperInvariant()}.json");
        candidates.Add($"{tenantPrefix}.appsettings.{envName.ToLowerInvariant()}.json");
    }

    foreach (var file in candidates)
    {
        configuration.AddJsonFile(file, optional: true, reloadOnChange: true);
    }

    configuration["Gateway:Tenant"] = tenant;
}

static bool IsApiRequest(HttpRequest request)
{
    if (request.Path.StartsWithSegments("/bff", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    if (string.Equals(request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    var accept = request.Headers.Accept.ToString();
    if (!string.IsNullOrEmpty(accept) && accept.Contains("application/json", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    return false;
}

static async Task SignOutAsync(HttpContext httpContext)
{
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await httpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
}
