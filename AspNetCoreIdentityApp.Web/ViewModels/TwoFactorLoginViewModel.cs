using AspNetCoreIdentityApp.Web.Models;
using System.ComponentModel.DataAnnotations;
using System.Runtime.InteropServices;

namespace AspNetCoreIdentityApp.Web.ViewModels
{
    public class TwoFactorLoginViewModel
    {
        [Display(Name = "Dogrulama Kodunuz")]
        [Required(ErrorMessage = "Dogruluma kodu bos olamaz")]
        public string VerificationCode { get; set; } = null!;
        public bool IsRememberMe { get; set; }
        public bool IsRecoverCode { get; set; }
        public TwoFactor TwoFactorType { get; set; }

    }
}
