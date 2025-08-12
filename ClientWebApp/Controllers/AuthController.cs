using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ClientWebApp.Controllers
{
    public class AuthController : Controller
    {
        public IActionResult Login(string returnUrl = "/")
        {
            return Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, "OpenIdConnect");
        }

        [Authorize]
        public IActionResult Profile()
        {
            return View(User.Claims);
        }

        public async Task<IActionResult> Logout()
        {
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
            var idToken = await HttpContext.GetTokenAsync("id_token");

            // Revoke refresh token
            if (!string.IsNullOrWhiteSpace(refreshToken))
            {
                var client = new HttpClient();
                var parameters = new Dictionary<string, string>
                {
                    ["token"] = refreshToken,
                    ["token_type_hint"] = "refresh_token",
                    ["client_id"] = "web-client"
                };

                var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7254/connect/revocation")
                {
                    Content = new FormUrlEncodedContent(parameters)
                };

                await client.SendAsync(revokeRequest);
            }

            // Then sign out of OpenID Connect + Identity session
            return SignOut(new AuthenticationProperties
            {
                RedirectUri = Url.Action("LogoutCallback", "Auth"),
                Parameters =
                {
                    { "id_token_hint", idToken }
                }
            },
            OpenIdConnectDefaults.AuthenticationScheme,
            CookieAuthenticationDefaults.AuthenticationScheme);
        }

        public IActionResult LogoutCallback()
        {
            return Redirect("/"); // or some logged-out confirmation page
        }
    }
}
