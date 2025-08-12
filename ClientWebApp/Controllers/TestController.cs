using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;

namespace ClientWebApp.Controllers
{
    public class TestController : Controller
    {
        [Authorize]
        public async Task<IActionResult> IndexAsync()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");

            var client = new HttpClient();

            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.GetAsync("https://localhost:7254/api/test");
            var content = await response.Content.ReadAsStringAsync();

            return Ok(content);
        }
    }
}
