using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace ClientWebApp.Middlewares
{
    public class TokenRefreshMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<TokenRefreshMiddleware> _logger;

        // simple per-request guard; for cross-request concurrency, use IMemoryCache + semaphore keyed by user
        private const string RefreshInProgressKey = "__refresh_in_progress";

        public TokenRefreshMiddleware(RequestDelegate next, ILogger<TokenRefreshMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            var auth = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!auth.Succeeded)
            {
                await _next(context);
                return;
            }

            // don't re-enter if something upstream already started a refresh
            if (context.Items.ContainsKey(RefreshInProgressKey))
            {
                await _next(context);
                return;
            }

            // read expires_at, or derive from access_token exp and persist
            var expiresAtString = await context.GetTokenAsync("expires_at");
            if (string.IsNullOrEmpty(expiresAtString))
            {
                var access = await context.GetTokenAsync("access_token");
                if (!string.IsNullOrEmpty(access))
                {
                    try
                    {
                        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(access);
                        var expUtc = jwt.ValidTo.ToUniversalTime();
                        expiresAtString = expUtc.ToString("o", CultureInfo.InvariantCulture);
                        auth.Properties.UpdateTokenValue("expires_at", expiresAtString);
                        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, auth.Principal, auth.Properties);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to derive expires_at from access token.");
                    }
                }
            }

            // parse expiry
            if (!string.IsNullOrEmpty(expiresAtString) &&
                DateTime.TryParse(expiresAtString, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var expiresAt))
            {
                var buffer = TimeSpan.FromMinutes(1);
                var now = DateTime.UtcNow.Add(buffer);
                var expiresAtTime = expiresAt;

                if (expiresAtTime <= now)
                {
                    var refresh = await context.GetTokenAsync("refresh_token");
                    if (string.IsNullOrEmpty(refresh))
                    {
                        _logger.LogInformation("No refresh_token in auth cookie; cannot refresh.");
                        await _next(context);
                        return;
                    }

                    // prevent concurrent refresh in same request
                    context.Items[RefreshInProgressKey] = true;

                    var result = await RefreshAsync(refresh, "web-client");
                    if (!result.Success)
                    {
                        _logger.LogWarning("Refresh failed ({StatusCode}): {Body}", result.StatusCode, result.Body ?? "(no body)");
                        // If invalid_grant, you can force a new login:
                        // await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);
                        // return;
                        context.Items.Remove(RefreshInProgressKey);
                        await _next(context);
                        return;
                    }

                    // update tokens in cookie (IMPORTANT: save the NEW refresh token)
                    auth.Properties.UpdateTokenValue("access_token", result.AccessToken);
                    if (!string.IsNullOrEmpty(result.RefreshToken))
                        auth.Properties.UpdateTokenValue("refresh_token", result.RefreshToken);

                    var newExp = DateTime.UtcNow.AddSeconds(result.ExpiresIn);
                    auth.Properties.UpdateTokenValue("expires_at", newExp.ToString("o", CultureInfo.InvariantCulture));

                    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, auth.Principal, auth.Properties);
                    _logger.LogInformation("Token refreshed. New expiry: {NewExp:o}", newExp);

                    context.Items.Remove(RefreshInProgressKey);
                }
            }
            else
            {
                _logger.LogDebug("No parsable expires_at; skipping refresh.");
            }

            await _next(context);
        }

        private static async Task<(bool Success, int StatusCode, string? Body, string AccessToken, string RefreshToken, int ExpiresIn)> RefreshAsync(string refreshToken, string clientId)
        {
            using var http = new HttpClient();

            // Avoid accidental caching proxies
            http.DefaultRequestHeaders.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true, NoStore = true };
            http.DefaultRequestHeaders.Pragma.TryParseAdd("no-cache");

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = clientId
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7254/connect/token")
            {
                Content = new FormUrlEncodedContent(form)
            };

            var res = await http.SendAsync(req);
            var body = await res.Content.ReadAsStringAsync();

            if (!res.IsSuccessStatusCode)
                return (false, (int)res.StatusCode, body, "", "", 0);

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            var at = root.GetProperty("access_token").GetString() ?? "";
            var rt = root.TryGetProperty("refresh_token", out var rtp) ? rtp.GetString() ?? "" : "";
            var exp = root.GetProperty("expires_in").GetInt32();

            return (true, (int)res.StatusCode, body, at, rt, exp);
        }
    }

}
