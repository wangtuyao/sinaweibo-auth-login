using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using hybrid.weibo_auth.provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Twitter.Messages;

namespace hybrid.weibo_auth
{
    public class WeiboAuthenticationOptions:AuthenticationOptions
    {
        public WeiboAuthenticationOptions(string authenticationType)
            : base(authenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-weibo");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        public string AppId { get; set; }

        public string AppSecret { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public IList<string> Scope { get; private set; }

        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public IWeiboAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }
    }
}