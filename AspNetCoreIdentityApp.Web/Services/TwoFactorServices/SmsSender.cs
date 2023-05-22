using Microsoft.Extensions.Options;

namespace AspNetCoreIdentityApp.Web.Services.TwoFactorServices
{
    public class SmsSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public SmsSender(IOptions<TwoFactorOptions> twoFactorOptions, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = twoFactorOptions.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string phoneNumber)
        {
            string code=_twoFactorService.GetCodeVerification().ToString();

            //sms provider codlanmasinin edeceyimiz yer buradi

            return code;
        }
    }
}
