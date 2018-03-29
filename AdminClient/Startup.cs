using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AdminClient
{
    public class Startup
    {
        private const string IdentityServerUrl = @"http://localhost:5000";

        private const string IdentityServerUrl_AuthorizeEndpoint = IdentityServerUrl + @"/connect/authorize";
        private const string IdentityServerUrl_LogoutEndpoint = IdentityServerUrl + @"/connect/endsession";
        private const string IdentityServerUrl_TokenEndpoint = IdentityServerUrl + @"/connect/token";
        private const string IdentityServerUrl_TokenRevocationEndpoint = IdentityServerUrl + @"/connect/revocation";
        private const string IdentityServerUrl_UserInfoEndpoint = IdentityServerUrl + @"/connect/userinfo";
        private const string Secret = "secret";

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("Cookies", options =>
            {
                options.Cookie.Name = "IDSAdminClient";
            })
            // ms middleware reads all claims from url and put into cookies
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = IdentityServerUrl;
                // require ssl
                options.RequireHttpsMetadata = false;
                options.ClientId = "mvc.implicit";
                options.ResponseType = "id_token";
                // ms has default scope like openid and profile
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Events.OnRedirectToIdentityProvider = (ctx) =>
                {
                    var impersonate = ctx.Properties.Items.FirstOrDefault(x => x.Key == "impersonate").Value;
                    if (!string.IsNullOrEmpty(impersonate))
                    {
                        ctx.ProtocolMessage.AcrValues = $"impersonate:{impersonate}";
                    }
                    return Task.FromResult(0);
                };
            });

            // prevent using a long weird claim type name
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }
    }
}
