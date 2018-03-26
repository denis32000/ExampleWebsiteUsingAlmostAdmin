using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ExampleWebsiteUsingAlmostAdmin.Models;
using Newtonsoft.Json;
using RestSharp;
using System.Security.Cryptography;
using System.Text;

namespace ExampleWebsiteUsingAlmostAdmin.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            //var t = JsonConvert.DeserializeObject<AnswerOnRequest>(
            //    "{\"QuestionId\":0,\"StatusCode\":4,\"StatusMessage\":\"Some of the data parameters are invalid.Check the documentation.\"}");
            AlmostAdminClient cl = new AlmostAdminClient(1, "test", "privateKey", "http://sdf.com/");
            var answer = cl.SendQuestion("test");
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }

    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    // TODO: REMOVE THIS, REFERENCE ALMOST ADMIN LIBRARY INSTEAD!!!!!!!!
    public class AlmostAdminClient
    {
        private string _apiRoute = "http://localhost:61555/api/question/";
        private int _projectId;
        private string _login;
        private string _statusUrl;
        private string _privateKey;

        public AlmostAdminClient(int projectId, string login, string projectPrivateKey, string statusUrl, string apiLink = null)
        {
            if (!string.IsNullOrEmpty(apiLink))
                _apiRoute = apiLink;

            _projectId = projectId;
            _login = login;
            _statusUrl = statusUrl;
            _privateKey = projectPrivateKey;
        }

        private string CreateSignature(string jsonData, string privateKey)
        {
            var base64EncodedData = CryptoUtils.Base64Encode(jsonData);
            var stringToBeHashed = privateKey + base64EncodedData + privateKey;
            var sha1HashedString = CryptoUtils.HashSHA1(stringToBeHashed);
            var base64EncodedSha1String = CryptoUtils.Base64Encode(sha1HashedString);

            return base64EncodedSha1String;
        }

        public AnswerOnRequest SendQuestion(string questionText)
        {
            try
            {
                if (string.IsNullOrEmpty(questionText))
                    return null;

                var question = new QuestionToApi
                {
                    Login = _login,
                    ProjectId = _projectId,
                    StatusUrl = _statusUrl,
                    Text = questionText
                };

                var questionJson = JsonConvert.SerializeObject(question);
                var signature = CreateSignature(questionJson, _privateKey);
                var data = CryptoUtils.Base64Encode(questionJson);

                var request = new RestRequest(Method.POST);
                request.AddParameter("data", data);
                request.AddParameter("signature", signature);

                var response = new RestClient(_apiRoute).Execute(request);

                var result = JsonConvert.DeserializeObject<AnswerOnRequest>(response.Content);
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }
    }
    public class AnswerOnRequest
    {
        public int QuestionId { get; set; }
        public int StatusCode { get; set; }
        public string StatusMessage { get; set; }
    }
    public class QuestionToApi
    {
        public int ProjectId { get; set; }
        public string Login { get; set; }
        public string Text { get; set; }
        public string StatusUrl { get; set; }
    }
    public static class CryptoUtils
    {
        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string HashSHA1(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    // can be "x2" if you want lowercase
                    sb.Append(b.ToString("x2"));
                }

                return sb.ToString();
            }
        }
        public static string CreateMD5(string input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);//ASCII
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private static string GetHexadecimalString(IEnumerable<byte> buffer)
        {
            return buffer.Select(b => b.ToString("x2")).Aggregate("", (total, cur) => total + cur);
        }
    }
}
