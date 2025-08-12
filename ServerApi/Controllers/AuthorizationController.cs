using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace ServerApi.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthorizationController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }
        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
        ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // ✅ 1. If user is not signed in, redirect to login page
            if (!User.Identity?.IsAuthenticated ?? true)
            {
                // 👇 This triggers the Identity login UI (e.g. /Account/Login?ReturnUrl=/connect/authorize)
                return Challenge(
                    authenticationSchemes: IdentityConstants.ApplicationScheme);
            }

            // ✅ 2. Get user info
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
                return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // ✅ 3. Build claims
            //var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
            //identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, user.Id.ToString()));
            //identity.AddClaim(new Claim(OpenIddictConstants.Claims.Email, user.Email ?? ""));

            //var roles = await _userManager.GetRolesAsync(user);
            //foreach (var role in roles)
            //{
            //    identity.AddClaim(new Claim(OpenIddictConstants.Claims.Role, role));
            //}
            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
            identity.AddClaim(new Claim(Claims.Subject, user.Id.ToString())
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            if (!string.IsNullOrEmpty(user.Email))
            {
                identity.AddClaim(new Claim(Claims.Email, user.Email)
                    .SetDestinations(Destinations.AccessToken, Scopes.Email));
            }

            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                var claim = new Claim(Claims.Role, role);
                var destinations = new List<string> { Destinations.AccessToken, Destinations.IdentityToken };
                claim.SetDestinations(destinations);
                identity.AddClaim(claim);
            }

            // ✅ 4. Build principal
            var principal = new ClaimsPrincipal(identity);

            // ✅ 5. Set scopes
            principal.SetScopes(request.GetScopes());
            principal.SetResources("resource_server");

            // ✅ 6. Return sign-in to complete the authorization code issuance
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        [HttpPost("~/connect/token")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
        ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (request.IsAuthorizationCodeGrantType())
            {
                // OpenIddict will deserialize the ClaimsPrincipal from the auth code
                var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                if (result is null || result.Principal is null)
                {
                    return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                return SignIn(result.Principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (request.IsRefreshTokenGrantType())
            {
                var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                if (result is null || result.Principal is null)
                    return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // (Optional) you could re-apply scopes/resources/claims here if needed.

                return SignIn(result.Principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return BadRequest(new OpenIddictResponse
            {
                Error = Errors.UnsupportedGrantType,
                ErrorDescription = "The specified grant type is not supported."
            });
        }
        [HttpGet("~/connect/logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

            return SignOut(new AuthenticationProperties
            {
                RedirectUri = "/" // this can be the home page or client callback URL
            }, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}
