﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved. Licensed under the Apache License, Version 2.0. See LICENSE in the project root for
// license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using QuickstartIdentityServer.Service;

namespace QuickstartIdentityServer
{
    public class Startup
    {
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseIdentityServer();

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            // configure identity server with in-memory stores, keys, clients and scopes
            var serverBuilder = services.AddIdentityServer()
                 .AddDeveloperSigningCredential();

            serverBuilder.AddAuthorizeInteractionResponseGenerator<ImpersonateAuthorizeInteractionResponseGenerator>();
            serverBuilder.AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddTestUsers(Config.GetUsers());
        }
    }
}
