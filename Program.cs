using System.Threading.RateLimiting;
using _233506D.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using _233506D.Services;
using _233506D.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<AuthDbContext>(options =>
	options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnection")));

builder.Services.AddDataProtection();

builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
    options.HttpsPort = 7165;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = "/Home/GeneralError";
});

var rateLimiterPolicy = "LoginRateLimit";
builder.Services.AddRateLimiter(options =>
{
    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.Redirect("/Error/RateLimitExceeded");
        await Task.CompletedTask;
    };
    options.AddPolicy(rateLimiterPolicy, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5, 
                Window = TimeSpan.FromMinutes(1), 
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            })
    );
});

builder.Services.Configure<ReCaptchaSettings>(builder.Configuration.GetSection("ReCaptcha"));
builder.Services.AddSingleton<ReCaptchaService>();

builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.AddSingleton<EmailService>();

builder.Services.AddIdentity<UserProfile, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;

});

builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())  
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";  
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20); 
    options.Cookie.HttpOnly = true; 
    options.Cookie.IsEssential = true; 
});

builder.Services.AddDistributedMemoryCache();

var app = builder.Build();
var scope = app.Services.CreateScope();
var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
var userManager = scope.ServiceProvider.GetRequiredService<UserManager<UserProfile>>();

string[] roles = { "Admin", "User" };

foreach (var role in roles)
{
    if (!await roleManager.RoleExistsAsync(role))
    {
        await roleManager.CreateAsync(new IdentityRole(role));
    }
}
using (scope)
{
    var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    var activeSessions = context.UserSessions.ToList();

    if (activeSessions.Any())
    {
        Console.WriteLine("Ensuring all users are logged out on application startup...");

        foreach (var session in activeSessions)
        {
            var user = context.Users.Find(session.UserId);
            if (user != null)
            {
                Console.WriteLine($"Logging out user: {user.Email}");
                context.AddAuditLog(user.Id, "Session expired due to application restart",
                    session.IPAddress, session.UserAgent);
            }
        }
        context.UserSessions.RemoveRange(activeSessions);
        context.SaveChanges();
    }
}

app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' https://www.google.com https://www.gstatic.com " +
            "https://ajax.aspnetcdn.com https://cdnjs.cloudflare.com " +
            "https://cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com " +
            "https://cdn.jsdelivr.net; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "frame-src 'self' https://www.google.com; " +
        "connect-src 'self' https://www.google.com https://www.gstatic.com " +
            "http://localhost:24654 ws://localhost:24654 wss://localhost:44391 " +
            "http://localhost:8339 ws://localhost:8339 " +
            "http://localhost:8339/9c1c34f95825456b986633a18a0e0201/browserLinkSignalR " +
            "wss://localhost:44395/233506D/ " +
            "http://localhost:7165 http://localhost:44395;");

    await next();
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Home/GeneralError");
    app.UseStatusCodePagesWithRedirects("/Home/GeneralError?statusCode={0}");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();

}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.UseRouting();
app.UseSession();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}");
app.Run();
