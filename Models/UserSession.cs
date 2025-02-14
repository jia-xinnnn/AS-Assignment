using System;
using System.ComponentModel.DataAnnotations;

namespace _233506D.Models
{
    public class UserSession
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string IPAddress { get; set; }

        [Required]
        public string UserAgent { get; set; }

        [Required]
        public DateTime LastLoginTime { get; set; }
    }
}
