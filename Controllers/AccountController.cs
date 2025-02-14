using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using _233506D.Models;
using _233506D.Data; 
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using _233506D.Services;
using Microsoft.Extensions.Options;
using System.Web;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using Google.Apis.Drive.v3.Data;

namespace _233506D.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<UserProfile> _signInManager;
        private readonly UserManager<UserProfile> _userManager;
        private readonly AuthDbContext _context;
        private readonly ILogger<AccountController> _logger;
        private readonly ReCaptchaService _reCaptchaService;
        private readonly IConfiguration _configuration;
        private readonly EmailService _emailService;

        public AccountController(UserManager<UserProfile> userManager, SignInManager<UserProfile> signInManager, 
            AuthDbContext context, ILogger<AccountController> logger, ReCaptchaService reCaptchaService, IConfiguration configuration, EmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _logger = logger;
            _reCaptchaService = reCaptchaService;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var csrfToken = HttpContext.Request.Form["__RequestVerificationToken"];

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model validation failed.");
                foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
                {
                    _logger.LogWarning($"Validation Error: {error.ErrorMessage}");
                }
                return View(model);
            }
            try
            {
                _logger.LogInformation($"Checking user for email: {model.Email}");

                var existingUser = await _userManager.FindByNameAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("Email", "This email is already registered. Please use another one.");
                    return View(model);
                }

                // Check if credit card number is exactly 16 digits
                if (!Regex.IsMatch(model.CreditCardNo, @"^\d{16}$"))
                {
                    ModelState.AddModelError("CreditCardNo", "Credit Card Number must be exactly 16 digits.");
                    return View(model);
                }

                var encryptedCreditCardNo = EncryptionHelper.Encrypt(model.CreditCardNo);


                var user = new UserProfile
                {
                    UserName = HttpUtility.HtmlEncode(model.Email),
                    Email = HttpUtility.HtmlEncode(model.Email),
                    FullName = HttpUtility.HtmlEncode(model.FullName),
                    NormalizedUserName = HttpUtility.HtmlEncode(model.Email).ToUpper(),
                    NormalizedEmail = HttpUtility.HtmlEncode(model.Email).ToUpper(),
                    Gender = HttpUtility.HtmlEncode(model.Gender),
                    MobileNo = HttpUtility.HtmlEncode(model.MobileNo ?? "N/A"),
                    CreditCardNo = EncryptionHelper.Encrypt(HttpUtility.HtmlEncode(model.CreditCardNo ?? "")),
                    DeliveryAddress = HttpUtility.HtmlEncode(model.DeliveryAddress ?? "N/A"),
                    AboutMe = HttpUtility.HtmlEncode(model.AboutMe ?? ""),
                    TwoFactorEnabled = false,
                    EmailConfirmed = false,
                    PhotoPath = SavePhoto(model.Photo)
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    _context.PasswordHistories.Add(new PasswordHistory
                    {
                        UserId = user.Id,
                        HashedPassword = user.PasswordHash,
                        CreatedAt = DateTime.UtcNow
                    });
                    await _context.SaveChangesAsync();
                    return RedirectToAction("Login");
                }

                _logger.LogWarning("User creation failed.");
                foreach (var error in result.Errors)
                {
                    _logger.LogWarning($"UserManager Error: {error.Description}");
                    ModelState.AddModelError("", error.Description);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Exception in Register: {ex.Message}");
                ModelState.AddModelError("", "An error occurred while processing your request.");
            }

            return View(model);
        }

		[HttpGet]
		public IActionResult Login([FromServices] IOptions<ReCaptchaSettings> reCaptchaSettings)
		{
			ViewBag.ReCaptchaSiteKey = reCaptchaSettings.Value.SiteKey;
			_logger.LogInformation("Login page loaded.");
			return View();
		}

		[HttpPost]
        [ValidateAntiForgeryToken]
        [EnableRateLimiting("LoginRateLimit")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var csrfToken = HttpContext.Request.Form["__RequestVerificationToken"];
            _logger.LogInformation($"CSRF Token Received in Login: {csrfToken}");
            _logger.LogInformation("Login form submitted.");

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model validation failed.");
                return View(model);
            }

            if (string.IsNullOrEmpty(model.RecaptchaToken))
            {
                _logger.LogError("reCAPTCHA token is missing from the request.");
                ModelState.AddModelError("", "reCAPTCHA token is missing. Please refresh and try again.");
                return View(model);
            }

            bool isCaptchaValid = await _reCaptchaService.VerifyReCaptchaAsync(model.RecaptchaToken);
            _logger.LogInformation($"reCAPTCHA Validation Result: {isCaptchaValid}");

            if (!isCaptchaValid)
            {
                _logger.LogWarning("reCAPTCHA verification failed.");
                ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                return View(model);
            }

            _logger.LogInformation("reCAPTCHA verification passed, proceeding with login.");

            var user = await _userManager.FindByNameAsync(model.Email);

            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(
                user.UserName, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in successfully.");
                LogAudit(user.Id, "User logged in");
                await _userManager.AddToRoleAsync(user, "User");

                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("FullName", user.FullName);
                HttpContext.Session.SetString("LastLogin", DateTime.UtcNow.ToString());

                string userIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                string userAgent = Request.Headers["User-Agent"].ToString();

                var newSession = new UserSession
                {
                    UserId = user.Id,
                    IPAddress = userIp ?? "Unknown",
                    UserAgent = userAgent,
                    LastLoginTime = DateTime.UtcNow
                };
                _context.UserSessions.Add(newSession);
                await _context.SaveChangesAsync();
                
                if (user.IsFirstLogin || user.TwoFactorEnabled)
                {
                    string otp = GenerateOTP();
                    HttpContext.Session.SetString("OTP", otp);
                    HttpContext.Session.SetString("UserId", user.Id);

                    await SendOTPEmail(user.Email, otp);

                    return RedirectToAction("VerifyOTP");
                }

                var passwordExpiryDays = 90; 
                if (user.LastPasswordChangeDate == null || (DateTime.UtcNow - user.LastPasswordChangeDate.Value).TotalDays > passwordExpiryDays)
                {
                    return RedirectToAction("ChangePassword");
                }

                ModelState.Clear();
                return RedirectToAction("Index", "Home");
            }

            if (result.IsLockedOut)
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                if (lockoutEnd <= DateTimeOffset.UtcNow)
                {
                    // Automatically unlock the account after the lockout period
                    await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow);
                    await _userManager.ResetAccessFailedCountAsync(user);
                    _logger.LogInformation($"User {user.Email} is automatically unlocked.");
                }
                else
                {
                    string unlockTime = lockoutEnd?.LocalDateTime.ToString("f") ?? "Unknown";
                    _logger.LogWarning($"User {user.Email} is locked out until {unlockTime}.");
                    ModelState.AddModelError("", $"Your account is locked. It will be unlocked at {unlockTime}.");
                    return View(model);
                }
            }

            else
            {
                ModelState.Clear(); 
                ModelState.AddModelError("", "Invalid email or password."); 
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!string.IsNullOrEmpty(userId))
            {
                LogAudit(userId, "User logged out");
            }

            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Session");
            await _signInManager.SignOutAsync();

            return RedirectToAction("Login", "Account");
        }

        private string SavePhoto(IFormFile photo)
        {
            if (photo == null || !ValidateFile(photo))
            {
                ModelState.AddModelError("Photo", "Invalid file format. Only JPG files are allowed.");
                return null;
            }

            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            var uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(photo.FileName);
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);

            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                photo.CopyTo(fileStream);
            }

            return $"/uploads/{uniqueFileName}";
        }

        private bool ValidateFile(IFormFile photo)
        {
            if (photo == null || photo.Length == 0)
            {
                return false;
            }

            var allowedExtensions = new List<string> { ".jpg", ".JPG", };
            var allowedMimeTypes = new List<string> { "image/jpeg", "image/pjpeg" };

            var fileExtension = Path.GetExtension(photo.FileName).ToLower();
            var mimeType = photo.ContentType.ToLower();

            if (!allowedExtensions.Contains(fileExtension) || !allowedMimeTypes.Contains(mimeType))
            {
                return false; 
            }
            const int maxFileSize = 2 * 1024 * 1024; 
            if (photo.Length > maxFileSize)
            {
                return false;  
            }

            return true;
        }

        public IActionResult CheckSession()
        {
            if (HttpContext.Session.GetString("UserId") == null)
            {
                return RedirectToAction("Login", "Account");
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public async Task<IActionResult> ForceLogout()
        {
            string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (!string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning($"Session expired for User ID: {userId}. Logging out...");
                LogAudit(userId, "Session expired, logging out"); 
            }
            else
            {
                _logger.LogWarning("Session expired, but no UserId found.");
            }

            await _signInManager.SignOutAsync();
            Response.Cookies.Delete(".AspNetCore.Session");
            Response.Cookies.Delete(".AspNetCore.Identity.Application");

            _logger.LogInformation("Session cleared successfully.");

            return RedirectToAction("Login", "Account");
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

        private string GenerateOTP()
        {
            Random random = new Random();
            return random.Next(100000, 999999).ToString(); 
        }

        private async Task SendOTPEmail(string email, string otp)
        {

            string subject = "Your 2FA OTP Code";
            string body = $"Your OTP Code is: {otp}. This code expires in 10 minutes.";

            try
            {
                await _emailService.SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to send OTP email to {email}: {ex.Message}");
            }
        }

        [HttpGet]
        public IActionResult VerifyOTP()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> VerifyOTP(VerifyOTPModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            string sessionOtp = HttpContext.Session.GetString("OTP");
            string userId = HttpContext.Session.GetString("UserId");

            if (sessionOtp == null || userId == null || model.OTP != sessionOtp)
            {
                ModelState.AddModelError("", "Invalid OTP. Please try again.");
                return View(model);
            }

            var userProfile = _context.UserProfiles.FirstOrDefault(u => u.Id == userId);
            if (userProfile != null)
            {
                userProfile.IsFirstLogin = false;
                userProfile.TwoFactorEnabled = true;
                userProfile.EmailConfirmed = true;
                _context.SaveChanges();
                LogAudit(userProfile.Id, "User succeeded in 2FA");
            }

            HttpContext.Session.Remove("OTP");

            await Task.CompletedTask; 

            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var minPasswordAgeDays = 3;
            if (user.LastPasswordChangeDate != null && (DateTime.UtcNow - user.LastPasswordChangeDate.Value).TotalDays < minPasswordAgeDays)
            {
                LogAudit(user.Id, "User denied password change request due to minimum age policy");
                var nextAllowedChange = user.LastPasswordChangeDate.Value.AddDays(minPasswordAgeDays);
                return RedirectToAction("PasswordChangeNotAllowed", new { nextChangeDate = nextAllowedChange });
            }
            return View();
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePassword model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (await IsPasswordReused(user, model.NewPassword))
            {
                ModelState.AddModelError("", "You cannot reuse your last 2 passwords.");
                return View(model);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                _context.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    HashedPassword = user.PasswordHash,
                    CreatedAt = DateTime.UtcNow
                });

                await _context.SaveChangesAsync();
                user.LastPasswordChangeDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                LogAudit(user.Id, "User changed password");
                return RedirectToAction("PasswordChangedSuccess");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult PasswordChangedSuccess()
        {
            
            return View();
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            if (string.IsNullOrEmpty(email) || !new EmailAddressAttribute().IsValid(email))
            {
                ModelState.AddModelError("", "Invalid email address.");
                return View();
            }

            var user = await _userManager.FindByNameAsync(email);
            if (user == null)
            {
                _logger.LogWarning($"Forgot Password: Email {email} not found in system.");
                ModelState.AddModelError("", "No account found with this email.");
                return View();
            }

            try
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                var resetLink = Url.Action("ResetPassword", "Account",
                    new { token, email = user.Email }, Request.Scheme);

                await _emailService.SendEmailAsync(user.Email, "Reset Password",
                    $"Click the link to reset your password: <a href='{resetLink}'>Reset Password</a>");
                LogAudit(user.Id, "User requested for reset password");
                _logger.LogInformation($"Reset password email sent to {user.Email}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error sending reset password email: {ex.Message}");
                ModelState.AddModelError("", "An error occurred while sending the reset email.");
                return View();
            }

            return View("ForgotPasswordConfirmation"); 
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                _logger.LogWarning("User not found for password reset.");
                ModelState.AddModelError("", "Invalid request.");
                return View();
            }

            var resetResult = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

            if (!resetResult.Succeeded)
            {
                foreach (var error in resetResult.Errors)
                {
                    _logger.LogError($"Password reset error: {error.Description}");
                    ModelState.AddModelError("", error.Description);
                }
                return View();
            }

            _logger.LogInformation($"User {user.Email} successfully reset their password.");
            LogAudit(user.Id, "User successfully reset their password");
            return RedirectToAction("Login", "Account"); 
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                return BadRequest("Invalid password reset request.");
            }

            var model = new ResetPasswordModel { Token = token, Email = email };
            return View(model); 
        }

        public async Task<bool> IsPasswordReused(UserProfile user, string newPassword)
        {
            var passwordHistory = await _context.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.CreatedAt)
                .Take(2) 
                .ToListAsync();

            foreach (var oldPassword in passwordHistory)
            {
                _logger.LogInformation("Checking...");
                if (await _userManager.CheckPasswordAsync(user, newPassword))
                    return true; 
            }

            return false;
        }

        [HttpGet]
        public IActionResult PasswordChangeNotAllowed(DateTime nextChangeDate)
        {

            ViewData["NextChangeDate"] = nextChangeDate.ToString("f");
            return View("~/Views/Error/PasswordChangeNotAllowed.cshtml");
        }

    }
}
