namespace Gateway.Config;

public static class TenantConfiguration
{
    public static void Configure(WebApplicationBuilder builder)
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
}
