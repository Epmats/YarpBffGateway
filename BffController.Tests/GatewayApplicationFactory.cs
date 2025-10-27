using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace BffController.Tests;

using Microsoft.Extensions.Configuration;
using System.Collections.Generic;

public class GatewayApplicationFactory : WebApplicationFactory<Program>
{
    public string DownstreamApiBaseUrl { get; set; }
    public string OidcServerUrl { get; set; }
    public bool UseExpiredToken { get; set; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration(config =>
        {
            config.AddInMemoryCollection(new[]
            {
                new KeyValuePair<string, string>("ReverseProxy:Clusters:cluster1:Destinations:destination1:Address", DownstreamApiBaseUrl),
                new KeyValuePair<string, string>("OpenIdConnect:Authority", OidcServerUrl),
                new KeyValuePair<string, string>("OpenIdConnect:ClientId", "test-client"),
                new KeyValuePair<string, string>("OpenIdConnect:Scope", "openid offline_access")
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication("Test")
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", options => { });

            services.AddSingleton<TestAuthHandler>(sp =>
            {
                var options = sp.GetRequiredService<IOptionsMonitor<AuthenticationSchemeOptions>>();
                var logger = sp.GetRequiredService<ILoggerFactory>();
                var encoder = sp.GetRequiredService<UrlEncoder>();
                return new TestAuthHandler(options, logger, encoder, UseExpiredToken);
            });
        });
    }
}

public class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly bool _isExpired;

    public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, bool isExpired = false)
        : base(options, logger, encoder)
    {
        _isExpired = isExpired;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new[] { new Claim(ClaimTypes.Name, "Test user") };
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties();

        if (_isExpired)
        {
            properties.StoreTokens(new[]
            {
                new AuthenticationToken { Name = "access_token", Value = "expired_access_token" },
                new AuthenticationToken { Name = "refresh_token", Value = "dummy_refresh_token" },
                new AuthenticationToken { Name = "expires_at", Value = System.DateTime.UtcNow.AddSeconds(-1).ToString("o") }
            });
        }
        else
        {
            properties.StoreTokens(new[]
            {
                new AuthenticationToken { Name = "access_token", Value = "dummy_access_token" }
            });
        }

        var ticket = new AuthenticationTicket(principal, properties, "Test");

        var result = AuthenticateResult.Success(ticket);

        return Task.FromResult(result);
    }
}
