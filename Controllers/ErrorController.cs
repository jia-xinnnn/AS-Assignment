using Microsoft.AspNetCore.Mvc;

namespace _233506D.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/RateLimitExceeded")]
        public IActionResult RateLimitExceeded()
        {
            return View();
        }
    }
}
