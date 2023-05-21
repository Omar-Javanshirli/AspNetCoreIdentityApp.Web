using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace AspNetCoreIdentityApp.Web.Services.TwoFactorServices
{
    public class EmailSender
    {
        private  readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public EmailSender(IOptions<TwoFactorOptions> twoFactorOptions, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = twoFactorOptions.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send (string emailAddress)
        {
            string code=_twoFactorService.GetCodeVerification().ToString();
            Exucute(emailAddress, code).Wait();
            return code;
        }

        private async Task Exucute( string email,string code)
        {
            var apiKey = _twoFactorOptions.SendGrid_ApiKey;

            var client= new SendGridClient(apiKey);

            var from = new EmailAddress("cvnsrliomn@gmail.com");

            var subject = "Iki addimli kimlik dogrulama kodunuz";

            var to= new EmailAddress(email);

            var htmlContent = @$"<h2>Siteye giris yapa bilmek icin dogrulama kodunuz asagidadir</h2>
                                <h3>Kodunuz : {code}</h3>";

            var msg=MailHelper.CreateSingleEmail(from,to,subject,null,htmlContent);

            var response=await client.SendEmailAsync(msg);
        }
       
    }
}
