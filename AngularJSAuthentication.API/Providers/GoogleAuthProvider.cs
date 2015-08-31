using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System.Threading.Tasks;
using System.Security.Claims;

namespace AngularJSAuthentication.API.Providers
{
    public class GoogleAuthProvider : IGoogleOAuth2AuthenticationProvider
    {
        //導向使用
        public void ApplyRedirect(GoogleOAuth2ApplyRedirectContext context)
        {
            //導向到 Google 的登入頁
            context.Response.Redirect(context.RedirectUri);
        }

        //G , F 驗證完畢 , 會透過 ASP.NET 預設的 http://localhost:1520/signin-google 進行導向。
        //而導向完後，就會進入底下方法，並且於 context 紀錄登入過後的資訊 ( 也就是說，取得相關資訊的事情..MS都處理掉了.. )
        public Task Authenticated(GoogleOAuth2AuthenticatedContext context)
        {
            //取得外部登入的存取 Token ，例如，取得存取 Google 帳號資訊的 Token
            context.Identity.AddClaim(new Claim("ExternalAccessToken", context.AccessToken));
            return Task.FromResult<object>(null);
        }

        //結束前會執行此行
        public Task ReturnEndpoint(GoogleOAuth2ReturnEndpointContext context)
        {
            return Task.FromResult<object>(null);
        }
    }
}