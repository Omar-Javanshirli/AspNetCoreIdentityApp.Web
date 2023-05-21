using AspNetCoreIdentityApp.Web.Extenisons;
using AspNetCoreIdentityApp.Web.Models;
using AspNetCoreIdentityApp.Web.Services.TwoFactorServices;
using AspNetCoreIdentityApp.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.CodeAnalysis.Completion;
using Microsoft.Extensions.FileProviders;
using System.Collections.Generic;
using System.Security.Claims;

namespace AspNetCoreIdentityApp.Web.Controllers
{
    [Authorize]
    public class MemberController : Controller
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly IFileProvider _fileProvider;
        private readonly TwoFactorService _twoFactorService;

        //contrelller-den basqa her hansisa bir yer de Httcontext-de catmax ucun bu interface-den istifade olunur
        //private readonly IHttpContextAccessor _contextAccessor;

        public MemberController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, IFileProvider fileProvider, TwoFactorService twoFactorService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _fileProvider = fileProvider;
            _twoFactorService = twoFactorService;
        }

        public async Task<IActionResult> Index()
        {
            //Cookie-icindeki datalara catmagin yontemi
            //var userClaims = User.Claims.ToList();
            //var email = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.Email);

            var currentUser = (await _userManager.FindByNameAsync(User.Identity!.Name!))!;

            var userViewModel = new UserViewModel
            {
                Email = currentUser.Email,
                UserName = currentUser.UserName,
                PhoneNumber = currentUser.PhoneNumber,
                PictureUrl = currentUser.Picture
            };

            return View(userViewModel);
        }

        public async Task Logout()
        {
            await _signInManager.SignOutAsync();
        }

        public IActionResult PasswordChange()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> PasswordChange(PasswordChangeViewModel request)
        {
            if (!ModelState.IsValid)
                return View();

            var currentUser = (await _userManager.FindByNameAsync(User.Identity!.Name!))!;
            var checkOldPassword = await _userManager.CheckPasswordAsync(currentUser, request.PasswordOld);

            if (!checkOldPassword)
            {
                ModelState.AddModelError(string.Empty, "Eski sifreniz yanlis");
                return View();
            }

            var resultChangePassword = await _userManager.ChangePasswordAsync(currentUser, request.PasswordOld, request.PasswordNew);

            if (resultChangePassword.Succeeded)
            {
                ModelState.AddModelErrorList(resultChangePassword.Errors);
                return View();
            }

            await _userManager.UpdateSecurityStampAsync(currentUser);
            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(currentUser, request.PasswordNew, true, false);

            TempData["SuccessMessage"] = "Sifreniz basari ile degistirilmisdir.";

            return View();
        }

        public async Task<IActionResult> UserEdit()
        {
            ViewBag.genderList = new SelectList(Enum.GetNames(typeof(Gender)));
            var currentUser = (await _userManager.FindByNameAsync(User.Identity!.Name!))!;

            var userEditViewMode = new UserEditViewModel
            {
                UserName = currentUser.UserName!,
                Phone = currentUser.PhoneNumber!,
                Email = currentUser.Email!,
                BirthDate = currentUser.BirthDate,
                Gender = currentUser.Gender,
                City = currentUser.City,
            };

            return View(userEditViewMode);
        }

        [HttpPost]
        public async Task<IActionResult> UserEdit(UserEditViewModel request)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var currentUser = (await _userManager.FindByNameAsync(User.Identity!.Name!))!;

            currentUser.UserName = request.UserName;
            currentUser.Email = request.Email;
            currentUser.PhoneNumber = request.Phone;
            currentUser.BirthDate = request.BirthDate;
            currentUser.City = request.City;
            currentUser.Gender = request.Gender;

            if (request.Picture != null && request.Picture.Length > 0)
            {
                var wwwrootFolder = _fileProvider.GetDirectoryContents("wwwroot");

                //Path.GetExtension => sekilin sonu hansi fortmadadisa onu yazdirsin mes: jpg,png ve.s;
                string randomFileName = $"{Guid.NewGuid().ToString()}{Path.GetExtension(request.Picture.FileName)}";

                var newPicturePath = Path.Combine(wwwrootFolder!.First(x => x.Name == "userpictures").PhysicalPath!, randomFileName);

                using var stream = new FileStream(newPicturePath, FileMode.Create);

                await request.Picture.CopyToAsync(stream);

                currentUser.Picture = randomFileName;
            }

            var updateToUserResult = await _userManager.UpdateAsync(currentUser);

            if (!updateToUserResult.Succeeded)
            {
                ModelState.AddModelErrorList(updateToUserResult.Errors);
                return View();
            }

            await _userManager.UpdateSecurityStampAsync(currentUser);
            await _signInManager.SignOutAsync();


            if (request.BirthDate.HasValue)
                await _signInManager.SignInWithClaimsAsync(currentUser, true, new[] { new Claim("birthdate", currentUser.BirthDate!.Value.ToString()) });

            else
                await _signInManager.SignInAsync(currentUser, true);


            TempData["SuccessMessage"] = "Üye bilgileri başarıyla değiştirilmiştir";

            var userEditViewModel = new UserEditViewModel()
            {
                UserName = currentUser.UserName!,
                Email = currentUser.Email!,
                Phone = currentUser.PhoneNumber!,
                BirthDate = currentUser.BirthDate,
                City = currentUser.City,
                Gender = currentUser.Gender,
            };

            return View(userEditViewModel);
        }

        [HttpGet]
        public IActionResult Claims()
        {
            var userClaimList = User.Claims.Select(x => new ClaimViewModel()
            {
                Issuer = x.Issuer,
                Type = x.Type,
                Value = x.Value
            }).ToList();

            return View(userClaimList);
        }


        [Authorize(Policy = "AnkaraPolicy")]
        [HttpGet]
        public IActionResult AnkaraPage()
        {
            return View();
        }

        [Authorize(Policy = "ExchangePolicy")]
        [HttpGet]
        public IActionResult ExchangePage()
        {
            return View();
        }


        [Authorize(Policy = "ViolencePolicy")]
        [HttpGet]
        public IActionResult ViolencePage()
        {
            return View();
        }

        public IActionResult AccessDenied(string ReturnUrl)
        {
            string message = string.Empty;

            message = "Bu sayfayı görmeye yetkiniz yoktur. Yetki almak için  yöneticiniz ile görüşebilirsiniz.";

            ViewBag.message = message;

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> TwoFactorWithAuthenticator()
        {
            var currentUser = _userManager.FindByNameAsync(User!.Identity!.Name!).Result;

            //Databasada UsersTokens Cedvelinde usere aid olan SharedKey-yin olub olmadigini yoxluyurug;
            string unFormattedKey = (await _userManager.GetAuthenticatorKeyAsync(currentUser!))!;

            if (string.IsNullOrEmpty(unFormattedKey))
            {
                //Bu method yeni bidene key yaradir eger key varsa bele yenisin yaradir
                await _userManager.ResetAuthenticatorKeyAsync(currentUser!);
                unFormattedKey = (await _userManager.GetAuthenticatorKeyAsync(currentUser!))!;
            }

            TwoFactorAuthViewModel twoFactorAuthViewModel = new TwoFactorAuthViewModel();

            twoFactorAuthViewModel.SharedKey = unFormattedKey;
            twoFactorAuthViewModel.AuthenticatorUri = _twoFactorService.GenerateQrCodeUri(currentUser!.Email!, unFormattedKey);

            return View(twoFactorAuthViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorWithAuthenticator(TwoFactorAuthViewModel request)
        {
            var currentUser = _userManager.FindByNameAsync(User!.Identity!.Name!).Result;

            var verificationCode = request.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            //Istifadecinin girdiyi dogrulama kodunun yoxlanilmasi
            var isTwoTokenValid = await _userManager.VerifyTwoFactorTokenAsync(currentUser!, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!isTwoTokenValid)
            {
                ModelState.AddModelError(string.Empty, "Girdiginiz dogrulama kodu yanlisdir");
                return View(request);
            }

            currentUser!.TwoFactorEnabled = true;
            currentUser!.TwoFactor = (sbyte)TwoFactor.MicrosoftGoogle;

            // istifadeci ucun qurtarma kodu yaradir.ikinci parametirde reqemi nece versey o qeder qurtarma kodu yaradir.
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(currentUser!, 5);

            TempData["recoverCodes"] = recoveryCodes;
            TempData["message"] = "Iki adimli dogrulama tipiniz olarak Microsoft/Google Authenticator olarak belirlenmistir";

            return RedirectToAction("TwoFactorAuth");
        }

        public IActionResult TwoFactorAuth()
        {
            var currentUser = _userManager.FindByNameAsync(User!.Identity!.Name!).Result;
            return View(new TwoFactorAuthViewModel() { TwoFactorType = (TwoFactor)currentUser!.TwoFactor! });
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorAuth(TwoFactorAuthViewModel request)
        {
            var currentUser = _userManager.FindByNameAsync(User!.Identity!.Name!).Result;
            switch (request.TwoFactorType)
            {
                case TwoFactor.None:
                    currentUser!.TwoFactorEnabled = false;
                    currentUser!.TwoFactor = (sbyte)TwoFactor.None;
                    TempData["message"] = "Iki adimli kimlik dogrulama tipiniz hic biri olarak guncellenmisdir";
                    break;

                case TwoFactor.MicrosoftGoogle:
                    return RedirectToAction("TwoFactorWithAuthenticator");

                case TwoFactor.Email:
                    currentUser!.TwoFactorEnabled = true;
                    currentUser.TwoFactor = (SByte)TwoFactor.Email;
                    TempData["message"] = "Iki Addimli dogrulama tipiniz email olarak belirlenmistir";
                    break;

            }

            await _userManager.UpdateAsync(currentUser!);
            return View(request);
        }
    }
}