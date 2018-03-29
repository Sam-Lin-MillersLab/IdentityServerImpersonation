using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiHost
{
    public class TestController : ControllerBase
    {
        [Route("test")]
        //[Authorize(AuthenticationSchemes = "Bearer")]
        [Authorize]
        public IActionResult Get()
        {
            //User.Claims;
            var claims = User.Claims.Select(x => x.Type + ":" + x.Value);
            return Ok(new { message = "Hello Web API!", claims=claims.ToArray()});
        }
    }
}
