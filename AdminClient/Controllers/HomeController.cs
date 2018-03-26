using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using AdminClient.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace AdminClient.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpPost]
        public async Task<IActionResult> Impersonate(ImpersonateViewModel impersonate)
        {
            Console.Write("impersonate account: {0}", impersonate.Account);
            User.Claims.Append(new Claim(nameof(impersonate), impersonate.Account));

            var props = new AuthenticationProperties
            {
                RedirectUri = "http://localhost:5003",
                Items =
                    {
                        { "returnUrl", "http://localhost:5002" },
                        { "scheme", "cookie" },
                        { nameof(impersonate), impersonate.Account}
                    }
            };
            // remove current cookies and call challenge to redirect back to IDS4 
            // therefor Admin site should get updated cookies with impersonate claim
            await HttpContext.SignOutAsync("Cookies");
            await HttpContext.SignOutAsync("oidc");
            return new ChallengeResult("oidc", props);
        }

        public IActionResult Index()
        {
            return View();
        }
    }

    public class ImpersonateViewModel
    {
        public string Account { get; set; }
    }
}
