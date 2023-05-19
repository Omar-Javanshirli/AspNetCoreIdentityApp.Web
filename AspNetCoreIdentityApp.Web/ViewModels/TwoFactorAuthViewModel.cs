using AspNetCoreIdentityApp.Web.Models;
using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Web.ViewModels
{
    public class TwoFactorAuthViewModel
    {
        public string? SharedKey { get; set; } 
        public string? AuthenticatorUri { get; set; }

        [Display(Name = "Dogrulama kodunuz")]
        [Required(ErrorMessage = "Dogrulama kodu gereklidir")]
        public string VerificationCode { get; set; } = null!;

        public TwoFactor TwoFactorType { get; set; } 
    }
}
