using System;
using System.Configuration;
using System.Text;
using System.Web;

namespace AzureWindowsAuthentication
{
    public class AzureWindowsAuthenticationModule : IHttpModule
    {
        private const string CookieName = "AzureAuthentication";
        private readonly string _realm;
        private readonly string _username;
        private readonly string _password;

        public AzureWindowsAuthenticationModule()
        {
            _realm = ConfigurationManager.AppSettings["AuthModule.Realm"];
            _username = ConfigurationManager.AppSettings["AuthModule.Username"];
            _password = ConfigurationManager.AppSettings["AuthModule.Password"];
        }

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += AuthenticateUser;

            context.EndRequest += IssueAuthenticationChallenge;
        }

        private void AuthenticateUser(Object source, EventArgs e)
        {
            var context = ((HttpApplication)source).Context;

            if(IsAuthenticated(context))
            {
                var authCookie = context.Request.Cookies.Get(CookieName);
                if (authCookie == null)
                {
                    //Remember the user for 3 days.
                    authCookie = new HttpCookie(CookieName, "1") {Expires = DateTime.Now.AddHours(6)};
                    context.Response.Cookies.Add(authCookie);
                }
            }
        }

        public void IssueAuthenticationChallenge(Object source, EventArgs e)
        {
            var context = ((HttpApplication)source).Context;

            if(!IsAuthenticated(context) && !IsCookieSet(context))
            {
                //Issue challenge
                context.Response.Clear();
                context.Response.StatusCode = 401;
                context.Response.AddHeader("WWW-Authenticate", "Basic realm =\"" + _realm + "\"");
            }
        }

        private bool IsCookieSet(HttpContext context)
        {
            var cookie = context.Request.Cookies.Get(CookieName);
            if (cookie == null)
                return false;

            return cookie.Value == "1";
        }

        private bool IsAuthenticated(HttpContext context)
        {
            var authorizationHeader = context.Request.Headers["Authorization"];

            string user;
            string pwd;
            if (!TryParseCredentials(authorizationHeader, out user, out pwd))
            {
                return false;
            }

            return ValidCredentials(user, pwd);

        }

        protected virtual bool ValidCredentials(string user, string pwd)
        {
            if(string.Equals(_username, user, StringComparison.CurrentCultureIgnoreCase) && string.Equals(_password, pwd, StringComparison.CurrentCultureIgnoreCase))
            {
                return true;
            }

            return false;
        }

        private bool TryParseCredentials(string fullAuthHeader, out string username, out string password)
        {
            username = string.Empty;
            password = string.Empty;

            if (string.IsNullOrEmpty(fullAuthHeader))
            {
                return false;
            }

            const string httpScheme = "Basic";
            
            if (!fullAuthHeader.StartsWith(httpScheme, StringComparison.CurrentCultureIgnoreCase))
            {
                return false;
            }

            var authHeader = fullAuthHeader.Substring(httpScheme.Length, fullAuthHeader.Length - httpScheme.Length).Trim();

            var usernamePair = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader));

            var parts = usernamePair.Split(':');

            if (parts.Length != 2)
            {
                return false;
            }

            username = parts[0];
            password = parts[1];

            return !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password);
        }

        public void Dispose()
        {

        }
    }
}
