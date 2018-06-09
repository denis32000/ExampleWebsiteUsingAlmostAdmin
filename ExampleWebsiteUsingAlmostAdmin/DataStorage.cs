using ExampleWebsiteUsingAlmostAdmin.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleWebsiteUsingAlmostAdmin
{
    public class DataStorage
    {
        public List<IApiResponse> AllResponsesFromAlmostAdmin { get; set; } = new List<IApiResponse>();
        public List<string> totalLogList = new List<string>();
    }
}
