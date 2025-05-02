using System.ComponentModel.DataAnnotations;
using ClassifiedDocumentPortal.Domain.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ClassifiedDocumentPortal.BlazorUi.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<PortalUser> _signInManager;
        private readonly UserManager<PortalUser> _userManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<PortalUser> signInManager, UserManager<PortalUser> userManager, ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }
        
        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            public string Username { get; set; }
            
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/documents");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(Input.Username, Input.Password, Input.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(Input.Username);

                    if (user is not null)
                    {
                        _logger.LogInformation(
                        $"User logged in. " +
                        $"Name: {user.Name}; " +
                        $"Email: {user.Email}; " +
                        $"Security Clearance: {user.SecurityClearance}; " +
                        $"Background Check Status: {user.BackgroundCheckStatusCompleted}; " +
                        $"Department of Defense Contractor Number: {user.DepartmentOfDefenseContractorNumber}; " +
                        $"US Federal Contractor Registration Number: {user.USFederalContractorRegistrationNumber}.");

                        // --- False Positive Examples ---

                        // 1. Example/Placeholder Data
                        var exampleSsn = "000-00-0000"; // Placeholder SSN for testing logs
                        _logger.LogInformation($"Example SSN logged for testing: {exampleSsn}");

                        // 2. Comment with sensitive pattern
                        // Example usage: apiClient.SetApiKey("FAKE_API_KEY_TO_REPLACE_12345");

                        // 3. Non-sensitive variable name
                        bool needsSecurityClearanceRecheck = (user.SecurityClearance == "Expired");
                        _logger.LogInformation($"User needs recheck: {needsSecurityClearanceRecheck}");

                        // --- End False Positive Examples ---

                        // --- Examples Expected to be Found by Scanner ---

                        // 1. Logging variable with sensitive name and realistic fake data
                        var exampleSsnForTesting = "000-00-0000"; // Fake SSN clearly marked as example/test data
                        _logger.LogInformation($"User SSN recorded during login: {exampleSsnForTesting}"); // Changed to LogInformation

                        // 2. Logging variable clearly indicating a secret
                        var secret = "sk_test_FAKE-KEY_123456789abcdef"; // Fake API Key (Renamed from apiSecretKey)
                        _logger.LogInformation($"API Secret Key used: {secret}"); // Changed to LogInformation

                        // 3. Logging email via a variable name suggesting credentials
                        var loginCredentialsEmail = user.Email;
                        _logger.LogInformation($"User credential email logged: {loginCredentialsEmail}");

                        // --- End Examples Expected to be Found ---
                    }
                    _logger.LogInformation($"EXAMPLE User SSN logged for testing purposes: {exampleSsnForTesting}");
                    _logger.LogInformation($"Test case using fake SSN: {exampleSsnForTesting}");
                    _logger.LogInformation($"Non-sensitive log entry (uses example SSN): {exampleSsnForTesting}");
                    _logger.LogInformation($"User SSN example recorded during login test: {exampleSsnForTesting}");
                    return LocalRedirect(returnUrl);
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Email or password are not correct.");

                    return Page();
                }
            }

            return Page();
        }
    }
}
