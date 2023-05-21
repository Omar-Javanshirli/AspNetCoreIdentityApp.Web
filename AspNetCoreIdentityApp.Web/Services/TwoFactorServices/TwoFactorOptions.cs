namespace AspNetCoreIdentityApp.Web.Services.TwoFactorServices
{
    public class TwoFactorOptions
    {
        public string SendGrid_ApiKey { get; set; }
        public int CodeTimeExpire { get; set; }
    }
}
