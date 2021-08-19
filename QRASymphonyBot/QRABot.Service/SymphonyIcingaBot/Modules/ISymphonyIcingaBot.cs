using DanskeBank.IcingaApiClient;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace QRASymphonyBot
{
    public interface ISymphonyIcingaBot
    {
        void AddElevatedUsers(List<string> elevatedUsers);
        void AddJiraCredentials(string jiraURL, string jiraURLCredentials);
        void PollIcingaHelper(List<Service> allServices, Dictionary<string, Dictionary<string, string>> icingaPollingFilters);
        Task RunClient();
        void SetSymphonyUserFilter(string buser);
        void SetupHttpHandler();
        void SetupProxyHttpHandler(string proxyUrl);
        void SetupVictorOps(string vopsURL, string ApiId, string ApiKey, IConfiguration vopsTeams);
    }
}