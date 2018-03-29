using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ApiHost
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("foobar", policy =>
                {
                    policy.WithOrigins("http://localhost:5000")
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                        //.WithHeaders("Accept", "Content-Type", "Authorization")
                        //.WithMethods("GET")
                });
            });
            services.AddMvc();

            services.AddAuthentication("Bearer")
                .AddIdentityServerAuthentication("Bearer", options=>
                {
                    options.Authority = "http://localhost:3308";
                    options.RequireHttpsMetadata = false;
                    options.ApiName = "api1";
                    options.ApiSecret = "secret";
                });

                //.AddJwtBearer("Bearer", options=>
                //{
                //    options.Authority = "http://localhost:3308";
                //    options.RequireHttpsMetadata = false;
                //    options.Audience = "api1";
                //});
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseCors("foobar");
            app.UseDeveloperExceptionPage();
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}
