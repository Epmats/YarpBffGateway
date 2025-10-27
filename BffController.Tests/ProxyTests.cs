using System.Net;
using System.Threading.Tasks;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;
using System.Text.Json;

namespace BffController.Tests;

public class ProxyTests : IClassFixture<GatewayApplicationFactory>, IAsyncLifetime
{
    private readonly GatewayApplicationFactory _factory;
    private WireMockServer _downstreamApi;
    private WireMockServer _oidcServer;

    public ProxyTests(GatewayApplicationFactory factory)
    {
        _factory = factory;
    }

    public Task InitializeAsync()
    {
        _downstreamApi = WireMockServer.Start();
        _oidcServer = WireMockServer.Start();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _downstreamApi.Stop();
        _oidcServer.Stop();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task AnonymousUser_ProxyCall_NoBearerToken()
    {
        _downstreamApi
            .Given(Request.Create().WithPath("/downstream/api").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200));

        _factory.DownstreamApiBaseUrl = _downstreamApi.Url;
        _factory.UseExpiredToken = false;
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/downstream/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AuthenticatedUser_ProxyCall_ForwardsBearerToken()
    {
        _downstreamApi
            .Given(Request.Create().WithPath("/downstream/api").UsingGet().WithHeader("Authorization", "Bearer dummy_access_token"))
            .RespondWith(Response.Create().WithStatusCode(200));

        _factory.DownstreamApiBaseUrl = _downstreamApi.Url;
        _factory.UseExpiredToken = false;
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Test");

        var response = await client.GetAsync("/api/downstream/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ExpiredToken_ProxyCall_RefreshesToken()
    {
        _oidcServer
            .Given(Request.Create().WithPath("/.well-known/openid-configuration").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new { token_endpoint = $"{_oidcServer.Url}/connect/token" }));

        _oidcServer
            .Given(Request.Create().WithPath("/connect/token").UsingPost()
                .WithHeader("Content-Type", "application/x-www-form-urlencoded")
                .WithBody(body =>
                    body.Contains("grant_type=refresh_token") &&
                    body.Contains("refresh_token=dummy_refresh_token") &&
                    body.Contains("client_id=test-client") &&
                    body.Contains("scope=openid offline_access")
                ))
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new { access_token = "new_access_token", refresh_token = "new_refresh_token" }));

        _downstreamApi
            .Given(Request.Create().WithPath("/downstream/api").UsingGet().WithHeader("Authorization", "Bearer expired_access_token"))
            .InScenario("Token Refresh")
            .WillSetStateTo("Token Expired")
            .RespondWith(Response.Create().WithStatusCode(401));

        _downstreamApi
            .Given(Request.Create().WithPath("/downstream/api").UsingGet().WithHeader("Authorization", "Bearer new_access_token"))
            .InScenario("Token Refresh")
            .WhenStateIs("Token Expired")
            .RespondWith(Response.Create().WithStatusCode(200));

        _factory.DownstreamApiBaseUrl = _downstreamApi.Url;
        _factory.OidcServerUrl = _oidcServer.Url;
        _factory.UseExpiredToken = true;
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Test");

        var response = await client.GetAsync("/api/downstream/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
