using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace hybrid.weibo_auth.provider
{
    public class WeiboReturnEndpointContext:ReturnEndpointContext
    {
        public WeiboReturnEndpointContext(IOwinContext context, 
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}