using System;
using System.Threading.Tasks;
using Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Linq;
using System.Security.Claims;
using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Owin.Security;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Extensions;

namespace UserClient
{
    public partial class Startup
    {
        public static string PublicClientId = "UserClient";
        private const string ClientUrl = @"http://localhost:5002";
        private const string IdentityServerUrl = @"http://localhost:5000";
        private const string IdentityServerUrl_AuthorizeEndpoint = IdentityServerUrl + @"/connect/authorize";
        private const string IdentityServerUrl_LogoutEndpoint = IdentityServerUrl + @"/connect/endsession";
        private const string IdentityServerUrl_TokenEndpoint = IdentityServerUrl + @"/connect/token";
        private const string IdentityServerUrl_TokenRevocationEndpoint = IdentityServerUrl + @"/connect/revocation";
        private const string IdentityServerUrl_UserInfoEndpoint = IdentityServerUrl + @"/connect/userinfo";
        private const string Secret = "secret";

        //private const short ExpireTimeSpan = 1;
        //private const string AuthenticationCookieName = "Mpix.Com.AuthCookie";
        public static void ConfigureAuth(IAppBuilder app)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            var jwtHandler = new JwtSecurityTokenHandler();
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                SlidingExpiration = true,
                CookieName = "UserClientAuth",
                Provider = new CookieAuthenticationProvider
                {
                    OnResponseSignedIn = async context =>
                    {
                        //var idToken = context.Identity.Claims.FirstOrDefault(c => c.Type == "id_token").Value;
                        //if (jwtHandler.CanReadToken(idToken))
                        //{
                        //    var token = jwtHandler.ReadJwtToken(idToken);
                        //    var guid = token.Claims.FirstOrDefault(c => c.Type == "sub").Value;

                        //    //aContext.SetUserID(Guid.Parse(guid), false);
                        //}
                        var guid = context.Identity.Claims.FirstOrDefault(c => c.Type == "sub").Value;
                    },
                    OnValidateIdentity = async context =>
                    {
                    }
                }
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = PublicClientId,
                ClientSecret = Secret,
                Authority = IdentityServerUrl,
                RedirectUri = ClientUrl + "/signin-oidc",
                PostLogoutRedirectUri = ClientUrl + "/signout-callback-oidc",
                ResponseType = "id_token",
                RequireHttpsMetadata = false,
                UseTokenLifetime = false,
                Scope = "openid profile",

                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                },

                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                AuthenticationType = "oidc",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async (notification) =>
                    {
                        // use the code to get the access and refresh token
                        var tokenClient = new TokenClient(IdentityServerUrl_TokenEndpoint, PublicClientId, Secret);

                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(notification.Code, notification.RedirectUri);

                        if (tokenResponse.IsError) { throw new Exception(tokenResponse.Error); }

                        // use the access token to retrieve claims from userinfo
                        var userInfoClient = new UserInfoClient(IdentityServerUrl_UserInfoEndpoint);

                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

                        // create new identity
                        var claimsIdentity = new ClaimsIdentity(notification.AuthenticationTicket.Identity.AuthenticationType, "name", "role");
                        claimsIdentity.AddClaims(userInfoResponse.Claims
                                .Where(x => x.Type != "sub") // filter sub since we're already getting it from id_token
                                .Select(x => new Claim(x.Type, x.Value)));

                        claimsIdentity.AddClaim(new Claim("id_token", notification.ProtocolMessage.IdToken));
                        claimsIdentity.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
                        claimsIdentity.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString()));
                        claimsIdentity.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));
                        claimsIdentity.AddClaim(new Claim("sid", notification.AuthenticationTicket.Identity.FindFirst("sid").Value));

                        notification.AuthenticationTicket = new AuthenticationTicket(claimsIdentity, notification.AuthenticationTicket.Properties);
                    },

                    RedirectToIdentityProvider = (notification) =>
                    {
                        // if signing out, add the id_token_hint
                        if (notification.ProtocolMessage.RequestType == Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Logout)
                        {
                            var idTokenHint = notification.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                            notification.ProtocolMessage.IdTokenHint = idTokenHint;
                        }

                        return Task.FromResult(0);
                    }
                }
            });
            app.UseStageMarker(PipelineStage.Authenticate);
        }
    }
}
