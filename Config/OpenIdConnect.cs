namespace Gateway.Config;

public class OpenIdConnect
{
    public string Authority { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string ClientSecret { get; set; } = default!;
    public string BearerTokenLocation { get; set; } = "access_token";
}

