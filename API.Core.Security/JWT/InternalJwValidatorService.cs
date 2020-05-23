using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWT.Experiments.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace API.Core.Security.JWT
{
    public static class InternalJwValidatorService
    {
        public static void AddInternalJwtAuthentication(this IServiceCollection services, InternalAPIAuthConfiguration config)
        {
            services.ConfigureRsaSecurityKey(config.Key);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options => ValidateUsingRsaSecurityKey(options, services, config));
        }

        private static void ValidateUsingSymmetricSecurityKey(JwtBearerOptions options, InternalAPIAuthConfiguration config)
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = config.Issuer,
                ValidAudience = config.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Key))
            };

            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                    {
                        context.Response.Headers.Add("Token-Expired", "true");
                    }

                    return Task.CompletedTask;
                }
            };
        }

        private static void ValidateUsingRsaSecurityKey(JwtBearerOptions options, IServiceCollection services, InternalAPIAuthConfiguration config)
        {
            IdentityModelEventSource.ShowPII = true;

            SecurityKey securityKey = services.BuildServiceProvider().GetRequiredService<RsaSecurityKey>();

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateLifetime = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = config.Issuer,
                ValidAudience = config.Audience,
                IssuerSigningKey = securityKey
                
            };

            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                    {
                        context.Response.Headers.Add("Token-Expired", "true");
                    }
                    else if (context.Exception.GetType() == typeof(SecurityTokenInvalidSignatureException))
                    {
                        context.Response.Headers.Add("Token-Invalid-Signature", "true");
                    }
                    
                    return Task.CompletedTask;
                },

                OnTokenValidated = context =>
                {
                    var principal = context.Principal;
                    var rawRoles = principal.FindFirstValue("http://wso2.org/claims/role");

                    if (rawRoles == null)
                        return Task.CompletedTask;

                    var roles = JsonConvert.DeserializeObject<IDictionary<string, string[]>>(rawRoles);
                    
                    var newClaims = roles[config.Property]
                        .Select(role => new Claim(ClaimTypes.Role, role)).ToList();

                    var propertyIdentity = new ClaimsIdentity(newClaims);

                    principal.AddIdentity(propertyIdentity);
                    
                    return Task.CompletedTask;
                }
            };
        }
    }
}