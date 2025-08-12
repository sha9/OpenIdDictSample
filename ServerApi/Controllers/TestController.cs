using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace ServerApi.Controllers
{
    public class TestController : ControllerBase
    {
        [Route("api/test")]
        [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Roles = "User")]
        [HttpGet]
        public string GetAuthorizedData()
        {
            return "This Is Authenticated Data";
        }
    }
}
