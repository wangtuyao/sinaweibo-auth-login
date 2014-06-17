using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(hybrid.Startup))]
namespace hybrid
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
