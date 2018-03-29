using ExampleWebsiteUsingAlmostAdmin.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleWebsiteUsingAlmostAdmin
{
    public class DataStorage
    {
        public List<AnswerOnRequest> AllResponsesFromAlmostAdmin { get; set; } = new List<AnswerOnRequest>();
    }
}
