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
                var fullAuthorizeUrl = (Request.Path + Request.QueryString).ToString();

                return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = fullAuthorizeUrl // 👈 preserve full /connect/authorize?... 
                });
            }

            // ✅ 2. Get user info
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
                return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // ✅ 3. Build claims
            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

            // sub
            identity.AddClaim(new Claim(Claims.Subject, user.Id.ToString())
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            // email
            if (!string.IsNullOrEmpty(user.Email))
            {
                var emailClaim = new Claim(Claims.Email, user.Email);
                var emailDest = new List<string> { Destinations.AccessToken };
                if (request.HasScope(Scopes.Email))
                    emailDest.Add(Destinations.IdentityToken);
                emailClaim.SetDestinations(emailDest);
                identity.AddClaim(emailClaim);
            }

            // (optional) name
            if (!string.IsNullOrEmpty(user.UserName))
            {
                var nameClaim = new Claim(Claims.Name, user.UserName);
                var nameDest = new List<string> { Destinations.AccessToken };
                if (request.HasScope(Scopes.Profile))
                    nameDest.Add(Destinations.IdentityToken);
                nameClaim.SetDestinations(nameDest);
                identity.AddClaim(nameClaim);
            }

            // roles
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                var claim = new Claim(Claims.Role, role);
                var roleDest = new List<string> { Destinations.AccessToken };
                if (request.HasScope(Scopes.Roles))
                    roleDest.Add(Destinations.IdentityToken);
                claim.SetDestinations(roleDest);
                identity.AddClaim(claim);
            }

            // ✅ 4. Build principal
            var principal = new ClaimsPrincipal(identity);
            principal.SetPresenters(request.ClientId!);

            // ✅ 5. Set scopes
            var allowed = new[]
            {
                Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Roles, Scopes.OfflineAccess
            };
            principal.SetScopes(allowed.Intersect(request.GetScopes()));
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
                var principal = result?.Principal ?? new ClaimsPrincipal();

                // Optional hardening: ensure user still valid
                var userId = principal.GetClaim(Claims.Subject);
                var user = string.IsNullOrEmpty(userId) ? null : await _userManager.FindByIdAsync(userId);
                if (user is null || !await _signInManager.CanSignInAsync(user))
                    return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // Rebuild a fresh identity (same pattern as in Authorize())
                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                identity.AddClaim(new Claim(Claims.Subject, user.Id.ToString())
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

                if (!string.IsNullOrEmpty(user.Email))
                {
                    var emailClaim = new Claim(Claims.Email, user.Email);
                    var emailDest = new List<string> { Destinations.AccessToken };
                    if (principal.HasScope(Scopes.Email))
                        emailDest.Add(Destinations.IdentityToken);
                    emailClaim.SetDestinations(emailDest);
                    identity.AddClaim(emailClaim);
                }

                if (!string.IsNullOrEmpty(user.UserName))
                {
                    var nameClaim = new Claim(Claims.Name, user.UserName);
                    var nameDest = new List<string> { Destinations.AccessToken };
                    if (principal.HasScope(Scopes.Profile))
                        nameDest.Add(Destinations.IdentityToken);
                    nameClaim.SetDestinations(nameDest);
                    identity.AddClaim(nameClaim);
                }

                var roles = await _userManager.GetRolesAsync(user);
                foreach (var role in roles)
                {
                    var rc = new Claim(Claims.Role, role);
                    var dest = new List<string> { Destinations.AccessToken };
                    if (principal.HasScope(Scopes.Roles))
                        dest.Add(Destinations.IdentityToken);
                    rc.SetDestinations(dest);
                    identity.AddClaim(rc);
                }

                var refreshed = new ClaimsPrincipal(identity);
                refreshed.SetScopes(principal.GetScopes());
                refreshed.SetResources("resource_server");
                refreshed.SetPresenters(principal.GetPresenters()); // keep client binding

                return SignIn(refreshed, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);   // optional
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

            return SignOut(new AuthenticationProperties { RedirectUri = "/" },
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}
