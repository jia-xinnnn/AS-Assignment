using System.ComponentModel.DataAnnotations;


namespace _233506D.Models
{
    public class RegisterModel
    {
        [Required]
        [StringLength(100)]
        [RegularExpression(@"^[A-Za-z\s]+$", ErrorMessage = "Full Name can only contain letters and spaces.")]
        public string FullName { get; set; } = String.Empty;


        [Required]
        [DataType(DataType.CreditCard)]
        public string CreditCardNo { get; set; } = String.Empty;

        [Required]
        public string Gender { get; set; } = String.Empty;

        [Required]
        [RegularExpression(@"^\d{8,15}$", ErrorMessage = "Mobile number must be 8 to 15 digits.")]
        public string MobileNo { get; set; } = String.Empty;


        [Required]
        [StringLength(200)]
        public string DeliveryAddress { get; set; } = String.Empty;

        [Required]
        [EmailAddress]
        [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    ErrorMessage = "Invalid email format. Please enter a valid email.")]
        public string Email { get; set; } = String.Empty;


        [Required]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{12,}$",
            ErrorMessage = "Password must be at least 12 characters long, and include uppercase, lowercase, number, and special character.")]
        public string Password { get; set; } = String.Empty;

        [Required]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; } = String.Empty;

        [Required]
        [DataType(DataType.Upload)]
        public IFormFile Photo { get; set; } = null;


        [Required]
        [StringLength(500)]
        public string AboutMe { get; set; } = String.Empty;
    }
}
