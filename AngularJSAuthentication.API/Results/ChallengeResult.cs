using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace AngularJSAuthentication.API.Results
{
    public class ChallengeResult : IHttpActionResult
    {        
        public string LoginProvider { get; set; }
        public HttpRequestMessage Request { get; set; }

        public ChallengeResult(string loginProvider, ApiController controller)
        {
            LoginProvider = loginProvider;
            Request = controller.Request;
        }

        //過程中會呼叫此方法，會透過Owin回傳連接網址
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            //傳入 Google 會觸發 Google Provider , Facebook 會觸發 Facebook provider
            Request.GetOwinContext().Authentication.Challenge(LoginProvider);

            //401
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            //取得 OAuth 完整連結...
            response.RequestMessage = Request;
            //會自動導向
            return Task.FromResult(response);
        }
    }
}