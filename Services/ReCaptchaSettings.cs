namespace _233506D.Services
{
	public class ReCaptchaSettings
	{
		public string SiteKey { get; set; }
		public string SecretKey { get; set; }
		public double MinimumScore { get; set; } = 0.7; 
	}
}
