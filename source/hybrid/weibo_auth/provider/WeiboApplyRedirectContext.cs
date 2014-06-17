using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace hybrid.weibo_auth.provider
{
    public class WeiboApplyRedirectContext:BaseContext<WeiboAuthenticationOptions>
    {
        public WeiboApplyRedirectContext(
            IOwinContext context, 
            WeiboAuthenticationOptions options,
            AuthenticationProperties properties, 
            string redirectUri)
            : base(context, options)
        {
        }

        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings", Justification = "Represents header value")]
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Gets the authenticaiton properties of the challenge
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }
    }
}