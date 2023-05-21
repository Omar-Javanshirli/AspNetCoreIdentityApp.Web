using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace AspNetCoreIdentityApp.Web.Services.TwoFactorServices
{
    public class TwoFactorService
    {
        //“otpauth://totp/{0} : {1} ?secret={2}&issuer={0}&digits=6” burdaki datalari gonderdiyimiz zaman encode elemey lazimdir
        //yani bir nov format elemey lazimdir ki gonderdiyimiz parametler duzgun gorsensin.Buna gore UrlConder Clasinda istifade ediriy.
        private readonly UrlEncoder _encoder;
        private readonly TwoFactorOptions _twoFactorOptions;

        public TwoFactorService(UrlEncoder encoder, IOptions<TwoFactorOptions> twoFactorOptions)
        {
            _encoder = encoder;
            _twoFactorOptions = twoFactorOptions.Value;
        }

        public string GenerateQrCodeUri(string email, string unFormattedKey)
        {
            const string format = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            return string.Format(format, _encoder.Encode("www.bidibidi.com"), _encoder.Encode(email), unFormattedKey);
        }

        public int GetCodeVerification()
        {
            Random rmd = new();
            return rmd.Next(1000, 9999);
        }

        public int TimeLeft(HttpContext context)
        {
            if (context.Session.GetString("currentTime") == null)
                context.Session.SetString("currentTime", DateTime.Now.AddSeconds(_twoFactorOptions.CodeTimeExpire).ToString());

            DateTime currentTime = DateTime.Parse(context.Session.GetString("currentTime")!.ToString());

            //totalSeconds => saniye formatinda deyer qaytarir
            int timeLeft = (int)(currentTime - DateTime.Now).TotalSeconds;

            if (timeLeft <= 0)
            {
                context.Session.Remove("currentTime");
                return 0;
            }
            return timeLeft;
        }
    }
}
