using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace QuickstartIdentityServer.Service
{
    public class ImpersonateAuthorizeInteractionResponseGenerator : AuthorizeInteractionResponseGenerator
    {
        private readonly IHttpContextAccessor _http;

        public ImpersonateAuthorizeInteractionResponseGenerator(
            ISystemClock clock,
            ILogger<AuthorizeInteractionResponseGenerator> logger,
            IConsentService consent,
            IProfileService profile,
            IHttpContextAccessor http)
            : base(clock, logger, consent, profile)
        {
            _http = http;
        }

        public override async Task<InteractionResponse> ProcessInteractionAsync(ValidatedAuthorizeRequest request, ConsentResponse consent = null)
        {
            var result = await base.ProcessLoginAsync(request);

            if (result.IsLogin || result.IsError) return result;

            var acr = request.GetAcrValues().FirstOrDefault(x => x.StartsWith("impersonate:"));
            if (acr != null)
            {
                if (request.Subject.HasClaim("name", "alice"))
                {
                    var target = acr.Split(':')[1];
                    if (target == "bob")
                    {
                        var newUser = new IdentityServerUser("2")
                        {
                            AdditionalClaims = {
                                new Claim("orignal_sub", request.Subject.FindFirstValue("sub")),
                            }
                        }.CreatePrincipal();

                        await _http.HttpContext.SignInAsync(newUser);
                        request.Subject = newUser;
                        return new InteractionResponse
                        {
                            RedirectUrl = "http://localhost:5002"
                        };
                    }
                }
            }

            return result;
        }

        protected override async Task<InteractionResponse> ProcessConsentAsync(ValidatedAuthorizeRequest request, ConsentResponse consent = null)
        {
            return await base.ProcessConsentAsync(request, consent);
        }

        protected override async Task<InteractionResponse> ProcessLoginAsync(ValidatedAuthorizeRequest request)
        {
            return await base.ProcessLoginAsync(request);
        }
    }
}
