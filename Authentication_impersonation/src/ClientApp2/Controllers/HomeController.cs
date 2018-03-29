using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ClientApp2.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;

namespace ClientApp2.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Logout()
        {
            //await HttpContext.SignOutAsync("Cookies");
            //await HttpContext.SignOutAsync("oidc");
            return SignOut(new AuthenticationProperties {
                    RedirectUri = "/Home/Index"
                },
                "Cookies", "oidc");
        }

        public async Task<IActionResult> Index()
        {
            var access_token = await HttpContext.GetTokenAsync("access_token");
            return View();
        }

        [Authorize]
        public IActionResult Secure()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
