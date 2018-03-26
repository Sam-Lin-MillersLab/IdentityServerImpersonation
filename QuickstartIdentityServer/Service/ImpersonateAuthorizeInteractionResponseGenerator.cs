using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

namespace QuickstartIdentityServer.Service
{
    public class ImpersonateAuthorizeInteractionResponseGenerator : AuthorizeInteractionResponseGenerator
    {
        public ImpersonateAuthorizeInteractionResponseGenerator(ISystemClock clock, ILogger<AuthorizeInteractionResponseGenerator> logger, IConsentService consent, IProfileService profile)
            : base(clock, logger, consent, profile)
        {
        }

        public override async Task<InteractionResponse> ProcessInteractionAsync(ValidatedAuthorizeRequest request, ConsentResponse consent = null)
        {
            var acr = request.GetAcrValues();
         
            if (request?.Client?.ClientId == "mvc.implicit")
            {
                // // TODO: Do some other behind the scenes check

                // var claims = new[] { new Claim(JwtClaimTypes.Name, "Fred Blogs"), new Claim(JwtClaimTypes.FamilyName, "Blogs"), new
                // Claim(JwtClaimTypes.GivenName, "Fred"), new Claim(JwtClaimTypes.Email, "fred.blogs@blogsandson.com"), };

                // var newPrincipal = IdentityServerPrincipal.Create("fred.blogs", "Fred Blogs", claims); request.Subject = newPrincipal;

                // return new InteractionResponse();
            }

            return await base.ProcessInteractionAsync(request, consent);
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
