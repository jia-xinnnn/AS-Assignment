using System.ComponentModel.DataAnnotations;

namespace _233506D.Models
{
    public class VerifyOTPModel
    {
        [Required]
        [Display(Name = "OTP Code")]
        public string OTP { get; set; }
    }

}
