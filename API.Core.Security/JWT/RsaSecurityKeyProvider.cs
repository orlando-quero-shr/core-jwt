using System;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Experiments.Configuration
{
    public static class RsaSecurityKeyProvider
    {
        public static void ConfigureRsaSecurityKey(this IServiceCollection services, string publicKey)
        {
            services.AddSingleton<RsaSecurityKey>(provider =>
            {
                var rsa = RSA.Create();

                rsa.ImportSubjectPublicKeyInfo(
                    source: Convert.FromBase64String(publicKey),
                    bytesRead: out _
                );

                return new RsaSecurityKey(rsa);
            });
        }
    }
}