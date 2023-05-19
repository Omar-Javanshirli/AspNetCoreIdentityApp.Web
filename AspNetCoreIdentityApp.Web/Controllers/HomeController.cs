using AspNetCoreIdentityApp.Web.Models;
using AspNetCoreIdentityApp.Web.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using AspNetCoreIdentityApp.Web.Extenisons;
using AspNetCoreIdentityApp.Web.Services;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace AspNetCoreIdentityApp.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<AppUser> _UserManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IEmailService _emailService;

        public HomeController(ILogger<HomeController> logger, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IEmailService emailService)
        {
            _logger = logger;
            _UserManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult SignUp()
        {
            return View();
        }

        public IActionResult SignIn()

        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignIn(SignInViewModel model, string? returnUrl = null)
        {

            if (!ModelState.IsValid)
            {
                return View();
            }

            //eger returnNull nuldursa Url.Action() isleyecey yoxa eger deger atanibsa returnNUll isleycey;
            returnUrl ??= Url.Action("Index", "Home");

            var hasUser = await _UserManager.FindByEmailAsync(model.Email);

            if (hasUser == null)
            {
                ModelState.AddModelError(string.Empty, "Email veya şifre yanlış");
                return View();
            }

            //var passwordCheck=await _UserManager.CheckPasswordAsync(hasUser, model.Password);

            //if (!passwordCheck)
            //{
            //    ModelState.AddModelError(string.Empty, "Email veya şifre yanlış");
            //    return View();
            //}

            // eger bu method ugurlu basa catsa bizim ucun bir cookie yaradacaq;
            var signInResult = await _signInManager.PasswordSignInAsync(hasUser, model.Password, model.RememberMe, true);

            if (signInResult.RequiresTwoFactor)
                return RedirectToAction("TwoFactorLogin");

            if (signInResult.IsLockedOut)
            {
                ModelState.AddModelErrorList(new List<string>() { "3 dakika boyunca giriş yapamazsınız." });
                return View();
            }

            if (!signInResult.Succeeded)
            {
                ModelState.AddModelErrorList(new List<string>() { $"Email veya şifre yanlış", $"Başarısız giriş sayısı = {await _UserManager.GetAccessFailedCountAsync(hasUser)}" });
                return View();
            }

            if (hasUser.BirthDate.HasValue)
            {
                //User Claim-larla beraber cookisini yaradir. Login olmax cookie yaratmaq demekdir.
                await _signInManager.SignInWithClaimsAsync(hasUser, model.RememberMe, new[] { new Claim("birthdate", hasUser.BirthDate.Value.ToString()) });
            }

            return Redirect(returnUrl!);

        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignUpViewModel request)
        {
            if (!ModelState.IsValid)
                return View();

            var identityResult = await _UserManager.CreateAsync(new()
            {
                UserName = request.UserName,
                PhoneNumber = request.Phone,
                Email = request.Email,
                TwoFactor = 0
            }, request.PasswordConfirm);

            if (!identityResult.Succeeded)
            {
                ModelState.AddModelErrorList(identityResult.Errors.Select(x => x.Description).ToList());
                return View();
            }

            var exchangeExpireClaim = new Claim("ExchangeExpireDate", DateTime.Now.AddDays(10).ToString());

            var user = await _UserManager.FindByNameAsync(request.UserName);

            // bir basa Databasada AspNetUserClaims cedveline yazilir AddClaimAsync methodu vasitesi ile.
            var claimResult = await _UserManager.AddClaimAsync(user!, exchangeExpireClaim);

            if (!claimResult.Succeeded)
            {
                // select -nen iceni girib xetanin description-larini elde ediriy.
                ModelState.AddModelErrorList(claimResult.Errors.Select(x => x.Description).ToList());
                return View();
            }

            TempData["SuccessMessage"] = "Üyelik kayıt işlemi başarıla gerçekleşmiştir.";

            return RedirectToAction(nameof(HomeController.SignIn));
        }

        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel request)
        {
            var hasUser = await _UserManager.FindByEmailAsync(request.Email);

            if (hasUser == null)
            {
                ModelState.AddModelError(String.Empty, "Bu email adresine sahip kullanıcı bulunamamıştır.");
                return View();
            }

            string passwordResestToken = await _UserManager.GeneratePasswordResetTokenAsync(hasUser);

            var passwordResetLink = Url.Action("ResetPassword", "Home", new { userId = hasUser.Id, Token = passwordResestToken }, HttpContext.Request.Scheme);
            //örnek link https://localhost:7006?userId=12213&token=aajsdfjdsalkfjkdsfj

            //email service
            await _emailService.SendResetPasswordEmail(passwordResetLink!, hasUser.Email!);

            TempData["SuccessMessage"] = "Şifre yenileme linki, eposta adresinize gönderilmiştir";

            return RedirectToAction(nameof(ForgetPassword));
        }

        public IActionResult ResetPassword(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel request)
        {
            var userId = TempData["userId"];
            var token = TempData["token"];

            if (userId == null || token == null)
            {
                throw new Exception("Bir hata meydana geldi");
            }

            var hasUser = await _UserManager.FindByIdAsync(userId.ToString()!);

            if (hasUser == null)
            {
                ModelState.AddModelError(String.Empty, "Kullanıcı bulunamamıştır.");
                return View();
            }

            IdentityResult result = await _UserManager.ResetPasswordAsync(hasUser, token.ToString()!, request.Password);

            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = "Şifreniz başarıyla yenilenmiştir";
            }
            else
            {
                ModelState.AddModelErrorList(result.Errors.Select(x => x.Description).ToList());
            }

            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl })!;

            //Facebooka giris ucun lazim olan propertiler
            var properities = _signInManager.ConfigureExternalAuthenticationProperties("Facebook", RedirectUrl);

            //ChallengeResult Parametre olarax ne qebul edirse itifadecini ora yonledirir;
            return new ChallengeResult("Facebook", properities);
        }

        public IActionResult GoogleLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl })!;

            //Facebooka giris ucun lazim olan propertiler
            var properities = _signInManager.ConfigureExternalAuthenticationProperties("Google", RedirectUrl);

            //ChallengeResult Parametre olarax ne qebul edirse itifadecini ora yonledirir;
            return new ChallengeResult("Google", properities);
        }

        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            //Login provider login provider key kimi melematlari ozunde saxliyir.
            //Login provider => hardan daxil olun facebook, google bu kimi melmatlari saxliyir
            //login provderKey => daxil oldugu mes(facebook, twitter) ve.s ordaki user idsidir.
            ExternalLoginInfo info = (await _signInManager.GetExternalLoginInfoAsync())!;

            if (info == null)
                return RedirectToAction("login");

            Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

            if (result.Succeeded)
                return Redirect(ReturnUrl);

            AppUser user = new AppUser();

            //facebookdan ve ya basqa bir saytdan gelen claimleri elde edirem. info.principial vasitesile edirem.
            user.Email = info.Principal.FindFirst(ClaimTypes.Email)?.Value;
            string externalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier)!.Value;

            if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
            {
                string userName = info.Principal.FindFirst(ClaimTypes.Name)!.Value;
                userName = userName?.Replace(' ', '-')?.ToLower() + externalUserId?.Substring(0, 5);
                user.UserName = userName;
            }
            else
                user.UserName = info.Principal.FindFirst(ClaimTypes.Email)?.Value;

            IdentityResult createResult = await _UserManager.CreateAsync(user);

            if (createResult.Succeeded)
            {
                //Databasada ki UserLogin Cedveline melumatlarin yazilmasi;
                var loginResult = await _UserManager.AddLoginAsync(user, info);
                if (loginResult.Succeeded)
                {
                    await _signInManager.SignInAsync(user, true);
                    return Redirect(ReturnUrl);
                }
                else
                    ModelState.AddModelError(string.Empty, "Failed to add external login.");
            }
            else
                ModelState.AddModelError(string.Empty, "Email or password is incorrect.");

            return RedirectToAction("Error");
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}