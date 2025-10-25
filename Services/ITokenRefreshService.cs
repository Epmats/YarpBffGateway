using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Gateway.Services;

public interface ITokenRefreshService
{
    Task<string?> RefreshTokenAsync(HttpContext httpContext);
}
