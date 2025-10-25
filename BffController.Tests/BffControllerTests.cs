using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Text.Json;

namespace BffController.Tests;

public class BffControllerTests : IClassFixture<GatewayApplicationFactory>
{
    private readonly GatewayApplicationFactory _factory;

    public BffControllerTests(GatewayApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task CheckSessionAsync_AuthenticatedUser_ReturnsOk()
    {
        // Arrange
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Test");

        // Act
        var response = await client.GetAsync("/bff/check_session");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task CheckSessionAsync_UnauthenticatedUser_ReturnsUnauthorized()
    {
        // Arrange
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        // Act
        var response = await client.GetAsync("/bff/check_session");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task CheckSessionAsync_UnauthenticatedUserWithReturnUrl_ReturnsUnauthorizedWithLoginUrl()
    {
        // Arrange
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-ReturnUrl", "https://example.com");

        // Act
        var response = await client.GetAsync("/bff/check_session");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("X-Login-Url"));
    }

    [Fact]
    public async Task Login_ReturnsChallengeResult()
    {
        // Arrange
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        // Act
        var response = await client.GetAsync("/bff/login");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    [Fact]
    public async Task Logout_AuthenticatedUser_ReturnsSignOutResult()
    {
        // Arrange
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Test");

        // Act
        var response = await client.PostAsync("/bff/logout", null);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    [Fact]
    public async Task StatusAsync_AuthenticatedUser_ReturnsOk()
    {
        // Arrange
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Test");

        // Act
        var response = await client.GetAsync("/bff/status");

        // Assert
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        var status = JsonSerializer.Deserialize<SessionStatusResponse>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.True(status.IsAuthenticated);
    }

    [Fact]
    public async Task StatusAsync_UnauthenticatedUser_ReturnsOk()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/bff/status");

        // Assert
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        var status = JsonSerializer.Deserialize<SessionStatusResponse>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.False(status.IsAuthenticated);
    }
}

public sealed record SessionStatusResponse(bool IsAuthenticated, bool HasRefreshToken, double? ExpiresInSeconds);