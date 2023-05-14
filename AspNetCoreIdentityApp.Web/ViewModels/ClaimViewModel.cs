namespace AspNetCoreIdentityApp.Web.ViewModels
{
    public class ClaimViewModel
    {
        //Claimler kim terefinden paylanilir onu oyrenmey ucun
        public string Issuer { get; set; } = null!;
        public string Type { get; set; } = null!;
        public string Value { get; set; } = null!;
    }
}
