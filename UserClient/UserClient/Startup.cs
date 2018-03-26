using System;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(UserClient.Startup))]

namespace UserClient
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var httpConfiguration = new HttpConfiguration();
            ConfigureAuth(app);
            //app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
        }
    }
}
