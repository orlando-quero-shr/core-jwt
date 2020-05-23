using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using JWT.Experiments.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Experiments.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class JWTController : ControllerBase
    {
        [HttpGet]
        public Object GenerateToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("12345678901234"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var permClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.GivenName, "Orlando"),
                new Claim(JwtRegisteredClaimNames.FamilyName, "Quero")
            };

            var token = new JwtSecurityToken("issuer",
                "audience",
                permClaims,
                expires:DateTime.Now.AddDays(1),
                signingCredentials: credentials);

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwtToken;
        }

        [HttpGet("claims")]
        public object GetName1()
        {
            if (!User.Identity.IsAuthenticated) return "Invalid";

            return User.Claims.Select(c =>
                new
                {
                    Type = c.Type,
                    Value = c.Value
                });

        }

        [Authorize(Roles = "pview-user")]
        [HttpPost("role-test")]
        public Object GetName2()
        {
            if (!(User.Identity is ClaimsIdentity identity)) return null;

            return User.Claims.Select(c =>
                new
                {
                    Type = c.Type,
                    Value = c.Value
                });
        }
    }
}