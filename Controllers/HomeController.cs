using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using _233506D.Models;
using _233506D.Data;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace _233506D.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly SignInManager<UserProfile> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly AuthDbContext _context; 

        public HomeController(ILogger<HomeController> logger, SignInManager<UserProfile> signInManager, IHttpContextAccessor httpContextAccessor, AuthDbContext context)
        {
            _logger = logger;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _context = context;
        }

        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                string userId = HttpContext.Session.GetString("UserId");

                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("Session expired. Logging user out.");

                    // Log the session expiration event
                    string userIdFromClaims = User.FindFirstValue(ClaimTypes.NameIdentifier);
                    if (!string.IsNullOrEmpty(userIdFromClaims))
                    {
                        LogAudit(userIdFromClaims, "Session expired, logging out");
                    }

                    // Properly log out the user
                    _signInManager.SignOutAsync().Wait();
                    HttpContext.Session.Clear();
                    Response.Cookies.Delete(".AspNetCore.Session");
                    Response.Cookies.Delete(".AspNetCore.Identity.Application");

                    return View();
                }

                var userProfile = _context.UserProfiles.FirstOrDefault(u => u.Id == userId);
                if (userProfile != null)
                {
                    ViewData["FullName"] = userProfile.FullName;
                    ViewData["Email"] = _context.Users.FirstOrDefault(u => u.Id == userId)?.Email;
                    ViewData["MobileNo"] = userProfile.MobileNo;
                    ViewData["DeliveryAddress"] = userProfile.DeliveryAddress;
                    ViewData["Gender"] = userProfile.Gender;
                    ViewData["CreditCardNo"] = EncryptionHelper.Decrypt(userProfile.CreditCardNo);
                    ViewData["PhotoPath"] = userProfile.PhotoPath;
                    ViewData["AboutMe"] = userProfile.AboutMe;
                }

                HttpContext.Session.SetString("LastLogin", DateTime.UtcNow.ToString());
                return View();
            }

            _logger.LogWarning("User is not authenticated. Redirecting to Login.");
            return View();
        }

        [Authorize(Roles = "Admin")]
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private void LogAudit(string userId, string action)
        {
            if (string.IsNullOrEmpty(userId)) return;

            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
                Timestamp = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "Singapore Standard Time")

            };

            _context.AuditLogs.Add(auditLog);
            _context.SaveChanges();
            _logger.LogInformation($"Audit Log Added: {action} for User {userId}");
        }
        [HttpGet]
        public IActionResult GeneralError(int? statusCode)
        {
            if (statusCode.HasValue)
            {
                ViewData["StatusCode"] = statusCode.Value;
            }
            else
            {
                ViewData["StatusCode"] = 500; // Default to internal server error
            }
            return View("~/Views/Error/GeneralError.cshtml");
        }


    }
}
