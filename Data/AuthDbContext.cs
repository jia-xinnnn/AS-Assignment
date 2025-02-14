using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using _233506D.Models;

namespace _233506D.Data
{
    public class AuthDbContext : IdentityDbContext<UserProfile>
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

        public DbSet<UserProfile> UserProfiles { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }
        public void AddAuditLog(string userId, string action, string ipAddress, string userAgent)
        {
            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                Timestamp = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "Singapore Standard Time"),
                IPAddress = ipAddress,
                UserAgent = userAgent
            };

            this.AuditLogs.Add(auditLog);
            this.SaveChanges();
        }

    }
}
