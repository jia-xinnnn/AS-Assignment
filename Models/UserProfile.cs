using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace _233506D.Models
{
    public class UserProfile: IdentityUser
    {

        [Required]
        public string Email { get; set; }

        [Required]
        public string FullName { get; set; }
        [Required]
        public string Gender { get; set; }
        [Required]
        public string MobileNo { get; set; }
        [Required]
        public string DeliveryAddress { get; set; }
        [Required]
        public string CreditCardNo { get; set; }
        [Required]
        public string PhotoPath { get; set; }
        [Required]
        public string AboutMe { get; set; }
        public bool IsFirstLogin { get; set; } = true;
        public DateTime? LastPasswordChangeDate { get; set; }

    }
}
