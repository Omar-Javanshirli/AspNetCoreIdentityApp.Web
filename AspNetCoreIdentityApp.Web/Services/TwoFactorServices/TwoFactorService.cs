using System.Text.Encodings.Web;

namespace AspNetCoreIdentityApp.Web.Services.TwoFactorServices
{
    public class TwoFactorService
    {
        //“otpauth://totp/{0} : {1} ?secret={2}&issuer={0}&digits=6” burdaki datalari gonderdiyimiz zaman encode elemey lazimdir
        //yani bir nov format elemey lazimdir ki gonderdiyimiz parametler duzgun gorsensin.Buna gore UrlConder Clasinda istifade ediriy.
        private readonly UrlEncoder _encoder;

        public TwoFactorService(UrlEncoder encoder)
        {
            _encoder = encoder;
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
    }
}
