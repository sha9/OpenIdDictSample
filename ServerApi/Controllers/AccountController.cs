using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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
        public async Task<IActionResult> Login(string returnUrl)
        {
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string email, string password, string returnUrl = "/")
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                // ⚠️ Sign the user in with Identity (sets auth cookie)
                var result = await _signInManager.PasswordSignInAsync(user, password, isPersistent: false, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    // 🔁 Redirect back to /connect/authorize to complete OIDC flow
                    return LocalRedirect(returnUrl);
                }
            }

            ModelState.AddModelError("", "Invalid login attempt");
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }
    }
}
