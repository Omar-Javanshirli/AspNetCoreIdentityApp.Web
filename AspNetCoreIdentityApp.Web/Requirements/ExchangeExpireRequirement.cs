using Microsoft.AspNetCore.Authorization;
using System.Net;
using System.Security.Claims;

namespace AspNetCoreIdentityApp.Web.Requirements
{
    public class ExchangeExpireRequirement : IAuthorizationRequirement
    {
        //bu classin yaranma sebebi bezi hallarda biz Program.cs terefinde bu classa parametre gonder isdiye bileriy
        //ona gore de biz burda bu classi yaradrix meselen Asagida gosderilen numune kimi;

        public int Age { get; set; }
    }

    public class ExchangeExpireRequirementHandler : AuthorizationHandler<ExchangeExpireRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ExchangeExpireRequirement requirement)
        {
            //requirement.Age = 12;

            if (!context.User.HasClaim(x => x.Type == "ExchangeExpireDate"))
            {
                context.Fail();
                return Task.CompletedTask;
            }

            var exchangeExpireDate = context.User.FindFirst("ExchangeExpireDate");

            if (DateTime.Now > Convert.ToDateTime(exchangeExpireDate!.Value))
            {
                context.Fail();
                return Task.CompletedTask;
            }

            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
