using AspNetCoreIdentityApp.Web.Models;
using AspNetCoreIdentityApp.Web.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using AspNetCoreIdentityApp.Web.Extenisons;
using AspNetCoreIdentityApp.Web.Services;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using AspNetCoreIdentityApp.Web.Services.TwoFactorServices;
using System.Runtime.InteropServices;

namespace AspNetCoreIdentityApp.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<AppUser> _UserManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly TwoFactorService _twoFactorService;
        private readonly EmailSender _emailSender;

        public HomeController(ILogger<HomeController> logger, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager,
            IEmailService emailService, TwoFactorService twoFactorService, EmailSender emailSender)
        {
            _logger = logger;
            _UserManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _twoFactorService = twoFactorService;
            _emailSender = emailSender;
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

            if (hasUser.TwoFactor == (int)TwoFactor.Email || hasUser.TwoFactor == (int)TwoFactor.Phone)
            {
                HttpContext.Session.Remove("currentTime");
            }

            if (signInResult.RequiresTwoFactor)
                return RedirectToAction("TwoFactorLogin", "Home", new { returnUrl = TempData!["ReturnUrl"]!.ToString() });

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

        public async Task<IActionResult> TwoFactorLogin(string ReturnUrl = "/")
        {
            //Bu method ilk once Identity.TwoFactorUserId adli cookie-den gedin user id-ni tapir.
            //daha sonra databasaya gedir bu userId-ye sahib userin melumatlarin tapib getirir.
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            TempData["ReturnUrl"] = ReturnUrl;

            switch ((TwoFactor)user!.TwoFactor!)
            {
                case TwoFactor.None:
                    break;
                case TwoFactor.Phone:
                    break;
                case TwoFactor.Email:

                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                        return RedirectToAction("SignIn");

                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);

                    //4 reqemli kodu emaila gonderib hemcinin hemen kodu sessionda saxlayiriq.
                    HttpContext.Session.SetString("codeverification", _emailSender.Send(user.Email!));

                    break;
                case TwoFactor.MicrosoftGoogle:
                    break;
                default:
                    break;
            }

            return View(new TwoFactorLoginViewModel() { TwoFactorType = (TwoFactor)user.TwoFactor });
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorLogin(TwoFactorLoginViewModel request)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            ModelState.Clear();

            bool isSuccessAuth = false;

            if ((TwoFactor)user!.TwoFactor! == TwoFactor.MicrosoftGoogle)
            {
                Microsoft.AspNetCore.Identity.SignInResult result = null;

                if (request.IsRecoverCode)
                    result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(request.VerificationCode);
                else
                    result = await _signInManager.TwoFactorAuthenticatorSignInAsync(request.VerificationCode, true, false);

                if (result.Succeeded)
                    isSuccessAuth = true;
                else
                    ModelState.AddModelError(string.Empty, "Dogrulama kodu yanlis");
            }

            if (user.TwoFactor == (sbyte)TwoFactor.Email || user.TwoFactor == (sbyte)TwoFactor.Phone)
            {
                ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                if (request.VerificationCode == HttpContext.Session.GetString("codeverification"))
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(user, request.IsRememberMe);
                    HttpContext.Session.Remove("currentTime");
                    HttpContext.Session.Remove("codeverification");
                    isSuccessAuth = true;
                }
                else
                    ModelState.AddModelError(string.Empty, "dogrulama kodu yanlisdir");
            }

            if (isSuccessAuth == true)
                return Redirect(TempData["ReturnUrl"]!.ToString()!);

            request.TwoFactorType = (TwoFactor)user.TwoFactor;
            return View(request);
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

        [HttpGet]
        public JsonResult AgainSendEmail()
        {
            try
            {
                var user = _signInManager.GetTwoFactorAuthenticationUserAsync().Result;
                HttpContext.Session.SetString("codeVerification", _emailSender.Send(user!.Email!));
                return Json(true);
            }
            catch (Exception)
            {
                //loglama yap;
                //istifadeciye xeta melumati goster;
                return Json(false);
            }
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}