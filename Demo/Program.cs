using System;
using System.Configuration;
using System.Net;

namespace duo_csharp
{
    class Program
    {
        private static string ikey;
        private static string skey;
        private static string akey;
        private static string host;
        private static string port;

        static void Main(string[] args)
        {
            ParseConfiguration();
            WebServer server = new WebServer(SendResponse, String.Format("http://localhost:{0}/", port));
            server.Run();
            PrintStartupMessaging();
            Console.ReadKey();
            server.Stop();
        }

        private static void PrintStartupMessaging()
        {
            Console.WriteLine("Server has been started.");
            Console.WriteLine("Visit the root URL with a 'user' argument, e.g.");
            Console.WriteLine(String.Format("'http://localhost:{0}/?user=myname'.", port));
            Console.WriteLine("Press any key to quit.");
        }

        private static void ParseConfiguration()
        {
            ikey = ConfigurationManager.AppSettings["ikey"];
            skey = ConfigurationManager.AppSettings["skey"];
            akey = ConfigurationManager.AppSettings["akey"];
            host = ConfigurationManager.AppSettings["host"];
            port = ConfigurationManager.AppSettings["port"];
        }

        public static string SendResponse(HttpListenerRequest request)
        {
            if (String.Compare(request.HttpMethod, "POST", true) == 0)
            {
                return doPost(request);
            }
            return doGet(request);
        }

        private static string doPost(HttpListenerRequest request)
        {
            using (System.IO.Stream body = request.InputStream)
            {
                using (System.IO.StreamReader reader = new System.IO.StreamReader(body, request.ContentEncoding))
                {
                    String bodyStream = reader.ReadToEnd();
                    var form = bodyStream.Split('=');
                    var sig_response_val = System.Net.WebUtility.UrlDecode(form[1]);
                    String responseUser = Duo.Web.VerifyResponse(ikey, skey, akey, sig_response_val);
                    if (String.IsNullOrEmpty(responseUser))
                    {
                        return "Did not authenticate with Duo.";
                    }
                    else
                    {
                        return String.Format("Authenticated with Duo as {0}.", responseUser);
                    }
                }
            }
        }

        private static string doGet(HttpListenerRequest request)
        {
            String response = String.Empty;

            try
            {
                response = System.IO.File.ReadAllText(System.IO.Path.GetFileName(request.RawUrl));
            }
            catch (Exception e)
            {
                String userName = request.QueryString.Get("user");
                if (String.IsNullOrEmpty(userName))
                    return String.Format("You must include a user to authenticate with Duo");

                var sig_request = Duo.Web.SignRequest(ikey, skey, akey, userName);
                response = String.Format(@"<html>
                  <head>
                    <title>Duo Authentication</title>
                    <meta name='viewport' content='width=device-width, initial-scale=1'>
                    <meta http-equiv='X-UA-Compatible' content='IE=edge'>
                    <link rel='stylesheet' type='text/css' href='Duo-Frame.css'>
                  </head>
                  <body>
                    <h1>Duo Authentication</h1>
                    <script src='/Duo-Web-v2.js'></script>
                    <iframe id='duo_iframe'
                            title='Two-Factor Authentication'
                            frameborder='0'
                            data-host='{0}'
                            data-sig-request='{1}'>
                    </iframe>
                  </body>
                </html>", host, sig_request);
            }

            return response;
        }
    }
}
