using Newtonsoft.Json;
using Microsoft.Extensions.Options;

namespace _233506D.Services
{
	public class ReCaptchaService
	{
		private readonly HttpClient _httpClient;
		private readonly string _secretKey;
		private readonly double _minimumScore;
		private readonly ILogger<ReCaptchaService> _logger;

		public ReCaptchaService(IOptions<ReCaptchaSettings> reCaptchaSettings, ILogger<ReCaptchaService> logger)
		{
			_httpClient = new HttpClient();
			_secretKey = reCaptchaSettings.Value.SecretKey;
			_minimumScore = reCaptchaSettings.Value.MinimumScore;
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		}

		public async Task<bool> VerifyReCaptchaAsync(string token)
		{

			if (string.IsNullOrEmpty(token))
			{
				return false;
			}

			var response = await _httpClient.PostAsync(
				"https://www.google.com/recaptcha/api/siteverify",
				new FormUrlEncodedContent(new Dictionary<string, string>
				{
					{ "secret", _secretKey },
					{ "response", token }
				})
			);

			var json = await response.Content.ReadAsStringAsync();

			try
			{
				dynamic result = JsonConvert.DeserializeObject(json);
				bool success = result.success == true;
				double score = result.score ?? 0.0;


				if (!success || score < _minimumScore)
				{
					_logger.LogWarning($"[WARNING] reCAPTCHA validation failed. Score too low: {score}");
					return false;
				}

				return true;
			}
			catch (Exception ex)
			{
				return false;
			}
		}
	}
}
