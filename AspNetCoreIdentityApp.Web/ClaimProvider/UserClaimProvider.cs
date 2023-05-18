using AspNetCoreIdentityApp.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AspNetCoreIdentityApp.Web.ClaimProviders
{
    //IClaimsTransformation => cookiden gelen datalari bizim claim obyektlerimze cevirdiyimiz hissedir 
    public class UserClaimProvider : IClaimsTransformation
    {
        private readonly UserManager<AppUser> _userManager;

        public UserClaimProvider(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

       
        //Cookie-ye datani eleve etmey hansiki bu data databasaya yazilmiyacax yalniz cookie-nin icinde qalacax.
        //Cooki-den datalar Claim-e cevrildiyi zaman her sefer bu method cagrilir ve isdeyir. Sadace Login olan userler ucun.
        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            //ClaimsIdentity => istifadecinin kimlik bilgileri Claimler terefinnen yaradilir
            var identityUser = principal.Identity as ClaimsIdentity;

            var currentUser = await _userManager.FindByNameAsync(identityUser!.Name!);
            
            if (String.IsNullOrEmpty(currentUser?.City))
                return principal;

            //city bizi databasadadki User cedvelinde yox idi biz bunu soradan elave etdik. buna gore de bu datalar calimlara yazilmir.
            //bele oldugu zaman biz dinamic yoxlanislar ede bilmiriy. buna gore biz bu melumati clamin icine elave ediry asagida 
            //gosterildiyi kimi
            if (principal.HasClaim(x => x.Type != "city"))
            {
                Claim cityClaim = new Claim("city", currentUser.City);
                identityUser.AddClaim(cityClaim);
            }

            return principal;
        }
    }
}
