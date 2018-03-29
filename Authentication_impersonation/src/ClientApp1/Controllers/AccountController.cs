using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ClientApp1.Models;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;

namespace ClientApp1.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Login()
        {
            var url = "http://localhost:3308/connect/authorize?client_id=client1&redirect_uri=http://localhost:2560/Account/Callback&response_type=id_token&response_mode=form_post&nonce=nonce&scope=openid profile officeInfo";
            return Redirect(url);
        }
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync("Cookies");
            return Redirect("~/");
        }

        [HttpPost]
        public async Task<IActionResult> Callback(string id_token, string error)
        {
            var certString = "MIIC6TCCAdGgAwIBAgIQLixNjyZMMqVFi+Jdu8VmAjANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDEwNzdHMwHhcNMTQxMjMxMjMwMDAwWhcNMTkxMjMxMjMwMDAwWjAOMQwwCgYDVQQDEwNzdHMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMcdzVjPPjMKaMYzvk1OvPMOkeF6gG3b2/Fdsy8u+w5AtDBIKtP4fFCdzFKRuZpMKEiNCARKu8+4kzeRi4QBeZGL+9wxg0jbfb7ae0tS5RpE4aWxmXcTu8hC7oCjT7KqwLrE7aqADpqdvzJIgwChwWVAAL8vzsG+HhmFJkNhnlvGpAIbzDCnmezGqdNgBRi5pleMiPqo2okUG6J52lCeLbBA8q1wzCtvbc+iegLgkRTGUso7iu3EZXmFcIoi/Djcuf2KHbWKoDBY0si/QifD2hOm29OcOxSoVyvFDTHhidDlCX4HWCNtZH53vh34uiws/F2SA46LnLx1PgLZNJbsJHAgMBAAGjQzBBMD8GA1UdAQQ4MDaAEDji3ClaURkjQzomnRqeCN6hEDAOMQwwCgYDVQQDEwNzdHOCEC4sTY8mTDKlRYviXbvFZgIwDQYJKoZIhvcNAQELBQADggEBAFCO5008ZA8McEi2UefY2MApJP6BSpfXtuscNzww1ASdrlKdNkR8iNF/60OOV2l+XyhqniyefcArApsOo6miJ8kLElCMiyJ0scHQETRBi0N80w+RXctmKzFmXUn1PL8rX5lUvQiKP0whZ+xyto3qsu6v0vj1p8JeBuuJYEmurUZa4ueWkUtHCL6wGQMqmKLBH7Rk6iLu3AP6hBHcHKq8Qu8owFfxmDMQh9v2hZUAAs0Y6pw3E1e2hyIQcZgMVZgfmxs7MYlCAloMWMxVTUk7mirOKRRzPK2HmTZtxCHE+py0mKhBa4vB+Ug8LBTDRQDNF9ZyKBKPBPEsEdS5YydIcrk=";
            var cert = new X509Certificate2(Convert.FromBase64String(certString));
            var key = new X509SecurityKey(cert);

            var param = new TokenValidationParameters {
                ValidIssuer = "http://localhost:3308",
                ValidAudience = "client1",
                IssuerSigningKey = key
            };

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();
            var claims = handler.ValidateToken(id_token, param, out _);

            var nonce = claims.FindFirst("nonce")?.Value;
            if (nonce == null || nonce != "nonce")
            {
                throw new Exception("Invalid nonce");
            }

            await HttpContext.SignInAsync("Cookies", claims);

            return Redirect("/Home/Secure");
        }
    }
}
