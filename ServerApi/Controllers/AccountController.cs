using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Client.WebIntegration;
using System.Security.Claims;

namespace ServerApi.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl)
        {
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            if(string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
                return View("AuthError", new AuthErrorVm
                {
                    Title = "Session expired",
                    Message = "Please start sign-in again.",
                    BackUrl = "https://localhost:7070/"
                });

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string email, string password, string returnUrl = "/")
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                // (Optional) enforce confirmed email:
                // if (!user.EmailConfirmed) { ModelState.AddModelError("", "Please confirm your email first."); ... }

                var result = await _signInManager.PasswordSignInAsync(
                    user, password, isPersistent: false, lockoutOnFailure: true);

                if (result.Succeeded)
                    return LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/connect/authorize");

                if (result.IsLockedOut)
                    ModelState.AddModelError("", "Account locked. Try later.");
                else if (result.RequiresTwoFactor)
                    ModelState.AddModelError("", "Two-factor required."); // or redirect to your 2FA flow
                else
                    ModelState.AddModelError("", "Invalid login attempt");
            }
            else
            {
                ModelState.AddModelError("", "Invalid login attempt");
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }
        // ---------- Register ----------
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl)
        {
            if (string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
                return View("AuthError", new AuthErrorVm
                {
                    Title = "Session expired",
                    Message = "Please start sign-in again.",
                    BackUrl = "https://localhost:7070/"
                });

            ViewData["ReturnUrl"] = returnUrl;
            return View(new RegisterViewModel());
        }

        [HttpPost, ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                ViewData["ReturnUrl"] = returnUrl;
                return View(model);
            }

            var existing = await _userManager.FindByEmailAsync(model.Email);
            if (existing != null)
            {
                ModelState.AddModelError("", "An account with this email already exists.");
                ViewData["ReturnUrl"] = returnUrl;
                return View(model);
            }

            var user = new ApplicationUser
            {
                Email = model.Email,
                UserName = model.Email,
                EmailConfirmed = true // in prod, set false and send confirmation email.
            };

            var create = await _userManager.CreateAsync(user, model.Password);
            if (!create.Succeeded)
            {
                foreach (var e in create.Errors) ModelState.AddModelError("", e.Description);
                ViewData["ReturnUrl"] = returnUrl;
                return View(model);
            }

            // Ensure role exists, then assign
            if (!await _userManager.IsInRoleAsync(user, "User"))
            {
                // If you didn't create the role in seeding, ensure it exists here via RoleManager
                // await _roleManager.CreateAsync(new IdentityRole<Guid>("User")); // if needed
                await _userManager.AddToRoleAsync(user, "User");
            }

            await _signInManager.SignInAsync(user, isPersistent: false);
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            return LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/connect/authorize");
        }

        // ---------- External (works from Login or Register) ----------

        [HttpGet("account/external/{provider}")]
        [AllowAnonymous]
        public IActionResult External(string provider, string? returnUrl = null)
        {
            if (string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
                return BadRequest("Missing returnUrl");

            // This is where WE want to go AFTER we process the provider response
            var props = new AuthenticationProperties
            {
                RedirectUri = returnUrl // keep the FULL authorize URL with client_id, scope, etc.
            };

            var scheme = provider switch
            {
                "LinkedIn" => OpenIddictClientWebIntegrationConstants.Providers.LinkedIn,
                "Google" => OpenIddictClientWebIntegrationConstants.Providers.Google,
                _ => throw new NotImplementedException(provider)
            };

            return Challenge(props, scheme);
        }


        [HttpGet("~/callback/login/{provider}"), HttpPost("~/callback/login/{provider}")]
        [AllowAnonymous]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> ExternalLoginCallback(string provider)
        {
            // 1) Principal from OpenIddict client
            var result = await HttpContext.AuthenticateAsync(
                OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

            if (result.Principal is not { Identity.IsAuthenticated: true })
                return LocalRedirect("/Account/Login"); // or show an error page

            // 2) Extract email (or fallback to a prompt page)
            var email =
                result.Principal.FindFirst(ClaimTypes.Email)?.Value ??
                result.Principal.FindFirst("email")?.Value;

            if (string.IsNullOrWhiteSpace(email))
            {
                // TODO: render a page asking for an email, then continue.
                return LocalRedirect(result.Properties?.RedirectUri ?? "/connect/authorize");
            }

            // 3) Find or create local user
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                user = new ApplicationUser
                {
                    Email = email,
                    UserName = email,
                    EmailConfirmed = true // in prod, choose your policy
                };

                var create = await _userManager.CreateAsync(user);
                await _userManager.AddToRoleAsync(user, "User");
                if (!create.Succeeded)
                    return LocalRedirect(result.Properties?.RedirectUri ?? "/connect/authorize");
            }

            if (!await _userManager.IsInRoleAsync(user, "User"))
                await _userManager.AddToRoleAsync(user, "User");

            // Link external login (idempotent)
            var providerKey =
                result.Principal.FindFirst("sub")?.Value ??
                result.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrEmpty(providerKey))
            {
                var already = await _userManager.FindByLoginAsync(provider, providerKey);
                if (already is null || already.Id == user.Id)
                    await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerKey, provider));
                else
                    return Forbid();
            }

            // 4) Sign in locally
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Optional: clear external cookie set during the handshake
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            // 5) Go back to the original /connect/authorize?...
            var returnUrl = result.Properties?.RedirectUri;
            if (string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
                return BadRequest("Missing or invalid returnUrl");

            return LocalRedirect(returnUrl);
        }

    }
}
