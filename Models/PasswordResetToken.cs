using System.ComponentModel.DataAnnotations;

namespace _233506D.Models
{
    public class PasswordResetToken
    {
        [Key]
        public string Token { get; set; } = Guid.NewGuid().ToString();  // Unique token
        public string UserId { get; set; }  // User association
        public DateTime ExpiryDate { get; set; } // Token expiration
    }

}
