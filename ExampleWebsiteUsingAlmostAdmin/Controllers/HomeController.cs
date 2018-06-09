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
        private DataStorage _dataStorage;

        // Almost admin: user defined constants
        private const int projectId = 3;
        private const string login = "d1@d.A";//"Denis3200000@yandex.ua";
        private const string projectPrivateKey = "b4644ea7-4419-4c6a-8949-c56cc0b3c82c";
        //



        public HomeController(DataStorage dataStorage)
        {
            _dataStorage = dataStorage;
        }

        public IActionResult Index()
        {
            //var t = JsonConvert.DeserializeObject<AnswerOnRequest>(
            //    "{\"QuestionId\":0,\"StatusCode\":4,\"StatusMessage\":\"Some of the data parameters are invalid.Check the documentation.\"}");
            return View();
        }

        [HttpPost]
        public JsonResult StatusFromAlmostAdmin([FromForm] string data, [FromForm]string signature)
        {
            if (!AlmostAdminClient.ValidateSignature(data, signature, projectPrivateKey))
            {
                return Json("Signature is not valid.");
            }

            //string answerJson;
            var decodedData = CryptoUtils.Base64Decode(data);
            //var questionToApi = JsonConvert.DeserializeObject<AnswerOnStatusUrl>(decodedData);

            //var t = JsonConvert.SerializeObject(decodedData);
            _dataStorage.totalLogList.Add(decodedData);

            return Json("*OK*"); // TODO: CHECK THIS VALUE
        }

        [HttpPost]
        public IActionResult OnlineForm(string fio, string text)
        {
            // TODO: change projectId and USE FIO PARAMETHER
            var returnUrl = Url.Action("StatusFromAlmostAdmin", "Home", null, Request.Scheme);

            var almostAdminClient = new AlmostAdminClient(
                projectId, 
                login,
                projectPrivateKey,
                returnUrl);

            var answer = almostAdminClient.SendQuestion(text, false);

            //var answer = new AnswerOnRequest { QuestionId = 1, StatusCode = Controllers.StatusCode.Success, StatusMessage = "SUCCESS WITH ME"};

            if (answer.StatusCode == Controllers.StatusCode.Success)
            {
                _dataStorage.AllResponsesFromAlmostAdmin.Add(answer); // save answer to storage to keep list of questionIds
            }

            var t = JsonConvert.SerializeObject(answer);
            _dataStorage.totalLogList.Add(t);

            return Ok();
        }

        [HttpPost]
        public IActionResult MailForm(string mail, string text)
        {
            var almostAdminClient = new AlmostAdminClient(
                projectId,
                login,
                projectPrivateKey,
                mail);

            var answer = almostAdminClient.SendQuestion(text, true);

            //var answer = new AnswerOnRequest { QuestionId = 1, StatusCode = Controllers.StatusCode.Success, StatusMessage = "SUCCESS WITH ME"};

            if (answer.StatusCode == Controllers.StatusCode.Success)
            {
                _dataStorage.AllResponsesFromAlmostAdmin.Add(answer); // save answer to storage to keep list of questionIds
            }

            var t = JsonConvert.SerializeObject(answer);
            _dataStorage.totalLogList.Add(t);

            return Ok();
        }

        [HttpPost]
        public IActionResult GetSimilar(string text)
        {
            var returnUrl = Url.Action("StatusFromAlmostAdmin", "Home", null, Request.Scheme);
            var almostAdminClient = new AlmostAdminClient(
                projectId,
                login,
                projectPrivateKey,
                returnUrl);

            var answer = almostAdminClient.GetSimilar(text);

            //var answer = new AnswerOnRequest { QuestionId = 1, StatusCode = Controllers.StatusCode.Success, StatusMessage = "SUCCESS WITH ME"};

            if (answer.StatusCode == Controllers.StatusCode.Success)
            {
                _dataStorage.AllResponsesFromAlmostAdmin.Add(answer); // save answer to storage to keep list of questionIds
            }

            var t = JsonConvert.SerializeObject(answer);
            _dataStorage.totalLogList.Add(t);

            return Ok();
        }
        
        [HttpPost]
        public IActionResult SendAnswer(int questId, string text)
        {
            var returnUrl = Url.Action("StatusFromAlmostAdmin", "Home", null, Request.Scheme);
            var almostAdminClient = new AlmostAdminClient(
                projectId,
                login,
                projectPrivateKey,
                returnUrl);

            var answer = almostAdminClient.SendAnswer(text, questId);

            //var answer = new AnswerOnRequest { QuestionId = 1, StatusCode = Controllers.StatusCode.Success, StatusMessage = "SUCCESS WITH ME"};

            if (answer.StatusCode == Controllers.StatusCode.Success)
            {
                _dataStorage.AllResponsesFromAlmostAdmin.Add(answer); // save answer to storage to keep list of questionIds
            }

            var t = JsonConvert.SerializeObject(answer);
            _dataStorage.totalLogList.Add(t);

            return Ok();
        }

        [HttpPost]
        public IActionResult GetQuestiion(int questId)
        {
            var returnUrl = Url.Action("StatusFromAlmostAdmin", "Home", null, Request.Scheme);
            var almostAdminClient = new AlmostAdminClient(
                projectId,
                login,
                projectPrivateKey,
                returnUrl);

            var answer = almostAdminClient.GetQuestion(questId);

            //var answer = new AnswerOnRequest { QuestionId = 1, StatusCode = Controllers.StatusCode.Success, StatusMessage = "SUCCESS WITH ME"};

            if (answer.StatusCode == Controllers.StatusCode.Success)
            {
                _dataStorage.AllResponsesFromAlmostAdmin.Add(answer); // save answer to storage to keep list of questionIds
            }

            var t = JsonConvert.SerializeObject(answer);
            _dataStorage.totalLogList.Add(t);

            return Ok();
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

        [HttpGet]
        public IActionResult Logs()
        {
            var htmlstr = String.Empty;
            int counter = 0;
            foreach(var i in _dataStorage.totalLogList)
            {
                counter++;
                htmlstr += "____________ " + counter + " ____________<br/>" + i + "<br/>";
            }
            return Content(htmlstr);
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
    public sealed class AlmostAdminClient
    {
        private string _apiQuestionRoute = "http://localhost:61555/api/question/";
        private string _apiAnswerRoute = "http://localhost:61555/api/answer/";
        private int _projectId;
        private string _login;
        private string _statusUrl;
        private string _privateKey;

        public AlmostAdminClient(int projectId, string login, string projectPrivateKey, string statusUrl, string apiLink = null)
        {
            if (!string.IsNullOrEmpty(apiLink))
                _apiQuestionRoute = apiLink;

            _projectId = projectId;
            _login = login;
            _statusUrl = statusUrl;
            _privateKey = projectPrivateKey;
        }

        public PostQuestionResponse SendQuestion(string questionText, bool email)
        {
            try
            {
                if (string.IsNullOrEmpty(questionText))
                    return null;

                var question = new PostQuestion
                {
                    Login = _login,
                    ProjectId = _projectId,
                    StatusUrl = _statusUrl,
                    Text = questionText,
                    AnswerToEmail = email
                };

                var questionJson = JsonConvert.SerializeObject(question);
                var signature = CreateSignature(questionJson, _privateKey);
                var data = CryptoUtils.Base64Encode(questionJson);

                var request = new RestRequest(Method.POST);
                request.AddParameter("data", data);
                request.AddParameter("signature", signature);

                var response = new RestClient(_apiQuestionRoute).Execute(request);

                var result = JsonConvert.DeserializeObject<PostQuestionResponse>(response.Content);
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public PostAnswerResponse SendAnswer(string answerText, int questionId)
        {
            try
            {
                if (string.IsNullOrEmpty(answerText))
                    return null;

                var question = new PostAnswer
                {
                    Login = _login,
                    ProjectId = _projectId,
                    AnswerText = answerText,
                    QuestionId = questionId
                };

                var questionJson = JsonConvert.SerializeObject(question);
                var signature = CreateSignature(questionJson, _privateKey);
                var data = CryptoUtils.Base64Encode(questionJson);

                var request = new RestRequest(Method.POST);
                request.AddParameter("data", data);
                request.AddParameter("signature", signature);

                var response = new RestClient(_apiAnswerRoute).Execute(request);

                var result = JsonConvert.DeserializeObject<PostAnswerResponse>(response.Content);
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public GetQuestionsResponse GetSimilar(string questionText)
        {
            try
            {
                if (string.IsNullOrEmpty(questionText))
                    return null;

                var question = new GetQuestions
                {
                    Login = _login,
                    ProjectId = _projectId,
                    Text = questionText,
                    SimilarMaxCount = 10
                };

                var questionJson = JsonConvert.SerializeObject(question);
                var signature = CreateSignature(questionJson, _privateKey);
                var data = CryptoUtils.Base64Encode(questionJson);

                var request = new RestRequest(Method.GET);
                request.AddParameter("data", data);
                request.AddParameter("signature", signature);

                var response = new RestClient("http://localhost:61555/api/find/").Execute(request);

                var result = JsonConvert.DeserializeObject<GetQuestionsResponse>(response.Content);
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public GetQuestionResponse GetQuestion(int id)
        {
            try
            {
                var question = new GetQuestion
                {
                    Login = _login,
                    ProjectId = _projectId,
                    QuestionId = id
                };

                var questionJson = JsonConvert.SerializeObject(question);
                var signature = CreateSignature(questionJson, _privateKey);
                var data = CryptoUtils.Base64Encode(questionJson);

                var request = new RestRequest(Method.GET);
                request.AddParameter("data", data);
                request.AddParameter("signature", signature);

                var response = new RestClient(_apiQuestionRoute).Execute(request);

                var result = JsonConvert.DeserializeObject<GetQuestionResponse>(response.Content);
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        internal static bool ValidateSignature(string base64EncodedData, string signature, string privateKey)
        {
            var stringToBeHashed = privateKey + base64EncodedData + privateKey;
            var sha1HashedString = CryptoUtils.HashSHA1(stringToBeHashed);
            var base64EncodedSha1String = CryptoUtils.Base64Encode(sha1HashedString);

            return base64EncodedSha1String == signature;
        }

        private string CreateSignature(string jsonData, string privateKey)
        {
            var base64EncodedData = CryptoUtils.Base64Encode(jsonData);
            var stringToBeHashed = privateKey + base64EncodedData + privateKey;
            var sha1HashedString = CryptoUtils.HashSHA1(stringToBeHashed);
            var base64EncodedSha1String = CryptoUtils.Base64Encode(sha1HashedString);

            return base64EncodedSha1String;
        }
    }

    public enum StatusCode
    {
        Success,
        Error,

        WrongLoginPasswordCredentials,
        WrongSignature,
        WrongData,
        WrongProjectId,
        WrongStatusUrl,

        // get response
        WrongQuestionId,

        AnswerByHuman,
        AnswerBySystem
    }

    public interface IApiRequest
    {
        bool IsModelValid();
        string Login { get; set; }
    }

    public interface IApiResponse
    {
        StatusCode StatusCode { get; set; }
        string StatusMessage { get; set; }
    }

    public class PostQuestion : IApiRequest
    {
        public int ProjectId { get; set; }
        public string Text { get; set; }
        public string StatusUrl { get; set; }
        public bool AnswerToEmail { get; set; }

        // IApiRequest
        public string Login { get; set; }
        public bool IsModelValid()
        {
            if (//Id > 0 && Id < Int32.MaxValue && 
                ProjectId > 0 && ProjectId < Int32.MaxValue &&
                !string.IsNullOrEmpty(Login) &&
                !string.IsNullOrEmpty(Text) &&
                !string.IsNullOrEmpty(StatusUrl))
                return true;

            return false;
        }
    }

    public class GetQuestion : IApiRequest
    {
        public int ProjectId { get; set; }
        public int QuestionId { get; set; }

        // IApiRequest
        public string Login { get; set; }
        public bool IsModelValid()
        {
            if (//Id > 0 && Id < Int32.MaxValue && 
                ProjectId > 0 && ProjectId < Int32.MaxValue &&
                QuestionId > 0 && QuestionId < Int32.MaxValue &&
                !string.IsNullOrEmpty(Login))
                return true;

            return false;
        }
    }

    public class GetQuestions : IApiRequest
    {
        public int ProjectId { get; set; }
        public string Text { get; set; }
        public int SimilarMaxCount { get; set; }

        // IApiRequest
        public string Login { get; set; }
        public bool IsModelValid()
        {
            if (//Id > 0 && Id < Int32.MaxValue && 
                ProjectId > 0 && ProjectId < Int32.MaxValue &&
                !string.IsNullOrEmpty(Login) &&
                !string.IsNullOrEmpty(Text) &&
                SimilarMaxCount > 0 && SimilarMaxCount < Int32.MaxValue)
                return true;

            return false;
        }
    }

    public class PostQuestionResponse : IApiResponse
    {
        public int QuestionId { get; set; }

        // IApiResponse
        public StatusCode StatusCode { get; set; }
        public string StatusMessage { get; set; }
    }

    public class GetQuestionResponse : IApiResponse
    {
        public int QuestionId { get; set; }
        public string QuestionText { get; set; }
        public DateTime Date { get; set; }
        public bool HasAnswer { get; set; }
        public string AnswerText { get; set; }

        // IApiResponse
        public StatusCode StatusCode { get; set; }
        public string StatusMessage { get; set; }
    }

    public class GetQuestionsResponse : IApiResponse
    {
        public string QuestionText { get; set; }
        public List<string> Questions { get; set; }

        // IApiResponse
        public StatusCode StatusCode { get; set; }
        public string StatusMessage { get; set; }
    }


    public class PostAnswer : IApiRequest
    {
        public int ProjectId { get; set; }
        public int QuestionId { get; set; }
        public string AnswerText { get; set; }

        // IApiRequest
        public string Login { get; set; }
        public bool IsModelValid()
        {
            if (//Id > 0 && Id < Int32.MaxValue && 
                ProjectId > 0 && ProjectId < Int32.MaxValue &&
                !string.IsNullOrEmpty(Login))
                return true;

            return false;
        }
    }
    public class PostAnswerResponse : IApiResponse
    {
        public int QuestionId { get; set; }

        // IApiResponse
        public StatusCode StatusCode { get; set; }
        public string StatusMessage { get; set; }
    }

    public class AnswerOnStatusUrl
    {
        public int QuestionId { get; set; }
        //public OperationType OperationType { get; set; } // QuestionToApi / AnswerToApi
        public StatusCode StatusCode { get; set; }
        public string StatusMessage { get; set; }

        public string QuestionText { get; set; }
        public string AnswerText { get; set; }

        //public bool AnswerToEmail { get; set; }
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
