using AspNetCoreIdentityApp.Web.OptionsModels;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace AspNetCoreIdentityApp.Web.Services
{
    public class EmailService : IEmailService
    {

        private readonly EmailSettings _emailSettings;

        public EmailService(IOptions<EmailSettings> options)
        {
            _emailSettings = options.Value;
        }

        public async Task SendResetPasswordEmail(string resetPasswordEmailLink, string ToEmail)
        {
            //Smtp Configuration
            var smtpClient = new SmtpClient();
            smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
            smtpClient.UseDefaultCredentials = false;
            smtpClient.Host = _emailSettings.Host;
            smtpClient.Port = 587;
            smtpClient.Credentials = new NetworkCredential(_emailSettings.Email, _emailSettings.Password);
            smtpClient.EnableSsl = true;

            //Message side
            var mailMessage = new MailMessage();

            //hansi email adresinnen mesaj gedecey onu bildirir;
            mailMessage.From = new MailAddress(_emailSettings.Email);

            //Gonderilecey message
            mailMessage.To.Add(ToEmail);

            //Message subject configuration
            mailMessage.Subject = "LocalHost | Sifre sifirlama linki";
            mailMessage.Body = @$"<h4>Sifrenizi yenilem ucun asagidaki linke tiklayiniz
                                    <p>
                                       <a href='{resetPasswordEmailLink}'>Sifre yenileme link</a>
                                    </p>
                                </h4>";
            mailMessage.IsBodyHtml = true;

            //send
            await smtpClient.SendMailAsync(mailMessage);
        }
    }
}
