using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web;
using hybrid.weibo_auth.provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Twitter;
using Microsoft.Owin.Security.Twitter.Messages;
using Owin;

namespace hybrid.weibo_auth
{
    public class WeiboAuthenticationMiddleware:AuthenticationMiddleware<WeiboAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public WeiboAuthenticationMiddleware(
            OwinMiddleware next,
             IAppBuilder app,
            WeiboAuthenticationOptions options)
            : base(next, options)
        {
            _logger = app.CreateLogger<WeiboAuthenticationMiddleware>();
            if(Options.Provider == null)
            {
                Options.Provider = new WeiboAuthenticationProvider();
            }
            if(Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(WeiboAuthenticationOptions).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new SecureDataFormat<RequestToken>(
                    Serializers.RequestToken,
                    dataProtector,
                    TextEncodings.Base64Url);
            }
            if(String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
            _httpClient = new HttpClient(new WebRequestHandler());
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            _httpClient.DefaultRequestHeaders.Accept.ParseAdd("*/*");
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin Twitter middleware");
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        protected override AuthenticationHandler<WeiboAuthenticationOptions> CreateHandler()
        {

            return new WeiboAuthenticationHandler(_httpClient, _logger);
        }

   
    }
}