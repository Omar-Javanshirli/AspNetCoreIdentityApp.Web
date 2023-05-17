using AspNetCoreIdentityApp.Web.ClaimProviders;
using AspNetCoreIdentityApp.Web.Extenisons;
using AspNetCoreIdentityApp.Web.Models;
using AspNetCoreIdentityApp.Web.OptionsModels;
using AspNetCoreIdentityApp.Web.PermissionsRoot;
using AspNetCoreIdentityApp.Web.Requirements;
using AspNetCoreIdentityApp.Web.Seeds;
using AspNetCoreIdentityApp.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SqlConn"));
});

//SecurityStamp Configuration
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromMinutes(30);
});

//IFileProvider interface-le isdediyimiz file cata bileriy.
builder.Services.AddSingleton<IFileProvider>(new PhysicalFileProvider(Directory.GetCurrentDirectory()));

//IHttpContextAccessor ucun...
//builder.Services.AddHttpContextAccessor();

builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));

//Extention method 
builder.Services.AddIdentityWithExt();

builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IClaimsTransformation, UserClaimProvider>();
builder.Services.AddScoped<IAuthorizationHandler, ExchangeExpireRequirementHandler>();
builder.Services.AddScoped<IAuthorizationHandler, ViolenceRequirementHandler>();

builder.Services.AddAuthorization(options =>
{

    options.AddPolicy("AnkaraPolicy", policy =>
    {
        policy.RequireClaim("city", "ankara");
    });

    options.AddPolicy("ExchangePolicy", policy =>
    {
        //Parametir gondermey ucun numunune   
        //policy.AddRequirements(new ExchangeExpireRequirement() { Age=11});
        policy.AddRequirements(new ExchangeExpireRequirement());
    });

    options.AddPolicy("ViolencePolicy", policy =>
    {
        policy.AddRequirements(new ViolenceRequirement() { ThresholdAge = 18 });
    });

    options.AddPolicy("OrderPermissionReadAndDelete", policy =>
    {
        policy.RequireClaim("permission", Permissions.Order.Read);
        policy.RequireClaim("permission", Permissions.Order.Delete);
        policy.RequireClaim("permission", Permissions.Stock.Delete);
    });

    options.AddPolicy("Permissions.Order.Read", policy =>
    {
        policy.RequireClaim("permission", Permissions.Order.Read);
    });

    options.AddPolicy("Permissions.Order.Delete", policy =>
    {
        policy.RequireClaim("permission", Permissions.Order.Delete);
    });


    options.AddPolicy("Permissions.Stock.Delete", policy =>
    {
        policy.RequireClaim("permission", Permissions.Stock.Delete);
    });
});

//Cookie optimization
builder.Services.ConfigureApplicationCookie(opt =>
{
    var cookieBuilder = new CookieBuilder();

    cookieBuilder.Name = "UdemyAppCookie";
    opt.LoginPath = new PathString("/Home/Signin");
    opt.LogoutPath = new PathString("/Member/logout");
    opt.AccessDeniedPath = new PathString("/Member/AccessDenied");
    opt.Cookie = cookieBuilder;
    opt.ExpireTimeSpan = TimeSpan.FromDays(60);

    //istifadeci 60 gun erzinde giris elese cookie-nin omru 60 gun uzancax "opt.SlidingExpiration" ture elediyimiz zaman.
    opt.SlidingExpiration = true;
});

var app = builder.Build();

//Yalniz bir defe isdiyicey
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<AppRole>>();

    await  PermissionSeed.Seed(roleManager);
}


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();