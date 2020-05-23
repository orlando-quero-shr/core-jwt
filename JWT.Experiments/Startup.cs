using API.Core.Security.JWT;
using JWT.Experiments.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace JWT.Experiments
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // load authentication configuration in this case
            // from the app settings
            var config = new InternalAPIAuthConfiguration();
            Configuration.GetSection("InternalAPIAuthConfig").Bind(config);

            // By executing the following we are registering the
            // necessary services used by hte authentication middleware
            // to validate the JWT token
            services.AddInternalJwtAuthentication(config);
            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseHttpsRedirection();

            app.UseRouting();

            // We need to enable the authentication middleware for this to work
            app.UseAuthentication();

            // This will allow the use of attributes such as [Authorize]
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
