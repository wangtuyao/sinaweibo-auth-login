using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace hybrid.weibo_auth.provider
{
    public class WeiboAuthenticatedContext:BaseContext
    {
        public WeiboAuthenticatedContext(IOwinContext context, 
            JObject accountInfo,
            string accessToken)
            : base(context)
        {
            IDictionary<string, JToken> userAsDictionary = AccountInfo;

            AccountInfo = accountInfo;
            AccessToken = accessToken;

            UserId = AccountInfo["id"].ToString();
            ScreenName = PropertyValueIfExists("screen_name", userAsDictionary);
        }

        public JObject AccountInfo { get; set; }

        public string UserId { get; private set; }

        public string ScreenName { get; private set; }

        public string AccessToken { get; private set; }

        public string AccessTokenSecret { get; private set; }

        public ClaimsIdentity Identity { get; set; }

        public AuthenticationProperties Properties { get; set; }

        private static string PropertyValueIfExists(string property, IDictionary<string, JToken> dictionary)
        {
            return dictionary.ContainsKey(property) ? dictionary[property].ToString() : null;
        }
    }
}