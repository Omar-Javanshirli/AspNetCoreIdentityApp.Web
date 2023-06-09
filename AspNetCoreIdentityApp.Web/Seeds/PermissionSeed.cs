﻿using AspNetCoreIdentityApp.Web.Models;
using AspNetCoreIdentityApp.Web.PermissionsRoot;
using Microsoft.AspNetCore.Identity;
using System.Data;
using System.Security.Claims;

namespace AspNetCoreIdentityApp.Web.Seeds
{
    public class PermissionSeed
    {
        public static async Task Seed(RoleManager<AppRole> roleManager)
        {
            var hasBasicRole = await roleManager.RoleExistsAsync("BasicRole");
            var hasAdvanceRole = await roleManager.RoleExistsAsync("AdvanceRole");
            var hasAdminRole = await roleManager.RoleExistsAsync("AdminRole");

            if (!hasBasicRole)
            {
                await roleManager.CreateAsync(new AppRole { Name = "BasicRole" });
                var basicRole = (await roleManager.FindByNameAsync("BasicRole"))!;

                await AddReadPermission(basicRole, roleManager);
            }

            if (!hasAdvanceRole)
            {
                await roleManager.CreateAsync(new AppRole { Name = "AdvanceRole" });
                var basicRole = (await roleManager.FindByNameAsync("AdvanceRole"))!;

                await AddReadPermission(basicRole, roleManager);
                await AddUpdateAndCreatePermission(basicRole, roleManager);
            }

            if (!hasAdminRole)
            {
                await roleManager.CreateAsync(new AppRole { Name = "AdminRole" });
                var basicRole = (await roleManager.FindByNameAsync("AdminRole"))!;

                await AddReadPermission(basicRole, roleManager);
                await AddUpdateAndCreatePermission(basicRole, roleManager);
                await AddDeletePermission(basicRole, roleManager);
            }

        }

        public static async Task AddReadPermission(AppRole role ,RoleManager<AppRole> roleManager)
        {
            //Rola Claim elave eliyir bu method. yani RoleClaims cedveline data elave edir.
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Stock.Read));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Order.Read));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Catalog.Read));
        }

        public static async Task AddUpdateAndCreatePermission(AppRole role, RoleManager<AppRole> roleManager)
        {
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Stock.Create));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Order.Create));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Catalog.Create));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Stock.Update));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Order.Update));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Catalog.Update));
        }

        public static async Task AddDeletePermission(AppRole role, RoleManager<AppRole> roleManager)
        {
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Stock.Delete));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Order.Delete));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permissions.Catalog.Delete));
        }

    }
}
