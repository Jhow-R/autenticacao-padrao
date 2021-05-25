using Newtonsoft.Json;
using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace AutenticacaoPadrao.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        public ActionResult Index(string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;

            var cookie = Request.Cookies[FormsAuthentication.FormsCookieName];
            if (cookie != null)
                return RedirectToAction(nameof(Index), "Home");

            return View();
        }

        public ActionResult Login(string user, string password, string returnUrl)
        {
            // Criação do Token de Authenticação padrão do ASP.NET
            var userData = JsonConvert.SerializeObject(new { User = user, Password = password });
            var ticket = new FormsAuthenticationTicket(1, user, DateTime.Now, DateTime.Now.Add(FormsAuthentication.Timeout), false, userData, FormsAuthentication.FormsCookiePath);
            var encryptedTicket = FormsAuthentication.Encrypt(ticket);
            var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);

            Response.Cookies.Add(cookie);

            if (Url.IsLocalUrl(returnUrl)
                && returnUrl.Length > 2
                && returnUrl.StartsWith("/")
                && !returnUrl.StartsWith("//"))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction(nameof(Index), "Home");
        }

        public ActionResult SignOut()
        {
            FormsAuthentication.SignOut();
            Request.Cookies.Remove(FormsAuthentication.FormsCookieName);
            return Redirect(FormsAuthentication.LoginUrl);
        }
    }
}