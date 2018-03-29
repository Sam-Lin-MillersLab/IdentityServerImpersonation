using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;

namespace AspNetCoreSecurity
{
    public class Config
    {
        public static List<Client> Clients = new List<Client> {
            new Client
            {
                ClientId = "spa",
                AllowedGrantTypes = GrantTypes.Implicit,
                RedirectUris ={
                    "http://localhost:5000/callback.html",
                    "http://localhost:5000/silent.html",
                },
                PostLogoutRedirectUris = {
                    "http://localhost:5000/index.html",
                },
                AllowedCorsOrigins = {
                    "http://localhost:5000"
                },
                AllowAccessTokensViaBrowser = true,
                AllowedScopes = { "openid", "officeInfo", "api1" }
            },
            new Client
            {
                ClientId = "console",
                ClientSecrets = { new Secret("secret".Sha256()) },
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                AllowedScopes = { "api1" },
                AccessTokenType = AccessTokenType.Reference,
            },
            new Client
            {
                ClientId= "client1",
                ClientName = "Sample Client 1",
                AllowedGrantTypes = GrantTypes.Implicit,
                RedirectUris = { "http://localhost:2560/Account/Callback" },
                RequireConsent = false,
                AllowedScopes = { "openid", "profile", "officeInfo" }
            },
            new Client
            {
                ClientId= "client2",
                ClientName = "Sample Client 2",
                AllowedGrantTypes = GrantTypes.Hybrid,
                ClientSecrets = { new Secret("secret".Sha256()) },
                RedirectUris = { "http://localhost:2563/signin-oidc" },
                FrontChannelLogoutUri = "http://localhost:2563/signout-oidc",
                //BackChannelLogoutUri = ""
                PostLogoutRedirectUris = { "http://localhost:2563/signout-callback-oidc" },
                RequireConsent = false,
                AllowOfflineAccess = true,
                AllowedScopes = { "openid", "profile", "officeInfo", "api1" },
                AbsoluteRefreshTokenLifetime = (int)TimeSpan.FromHours(24).TotalSeconds,
                //RefreshTokenUsage = TokenUsage.OneTimeOnly
            },
        };

        public static List<ApiResource> ApiResources = new List<ApiResource>()
        {
            new ApiResource("api1", "My API 1")
            {
                ApiSecrets = { new Secret("secret".Sha256()) }
            }
        };

        public static List<IdentityResource> IdentityResources = new List<IdentityResource> {
            new IdentityResources.OpenId(),
            //new IdentityResource("openid", new[]{ "sub" }),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResources.Phone(),
            new IdentityResource("officeInfo", new[]{ "officePhone", "officeLocation" })
        };
    }
}
