using DanskeBank.IcingaApiClient;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;

namespace QRASymphonyBot
{
    class IcingaClient
    {
        #region Members
        public IcingaApiClient API = null;
        private IConfiguration Configuration;
        static ILogger Logger;
        private readonly bool Debug = false;
        #endregion

        #region c-tors
        public IcingaClient() { throw new NotImplementedException("Need a config constructor!"); }

        public IcingaClient(IConfiguration configuration, String environment, ILogger logger, bool debug = false)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            Debug = debug;
            if (Init() && Debug) Logger.LogInformation("IcingaClient initialized successfully for env=" + environment + "!");
        }
        #endregion

        #region Methods
        //icinga test
        //IC = new IcingaClient(Configuration[IcingaEnv], IcingaEnv, Logger, Debug);
        //var IcingaService = await IC.TryGetServiceAsync("QRA_Intraday", "QicingaInject");
        //var IcingaService = await IC.GetServiceAsync("QRA_Intraday", "QicingaInject");
        //var IcingaHost = await IC.API.GetHostAsync("QRA_Intraday");
        //var b = IcingaService.Attributes;
        //var u = await IC.API.UpdateServiceAsync("QRA_Intraday", "QicingaInject",b);
        //var newAttributes = new Dictionary<String, String> { { "errors", "some weird test" }, { "warnings", "errorTradeHandling" } };
        //var update = await IC.Update(IcingaService, newAttributes);


        public async Task<bool> Update(Service service, Dictionary<String,String> newattributes)
        {
            var crntVars = service.Attributes.Vars;
            var crntAttrs = service.Attributes;
            var outVars = new ServiceAttributes();
            outVars.Vars = new Dictionary<string, object>();
            foreach (var kv in crntVars)
                outVars.Vars[kv.Key] = kv.Value;

            foreach (var kv in newattributes)
            {
                if (typeof(ServiceAttributes).GetProperty(kv.Key) != null)//this is not a var
                {
                    System.Reflection.PropertyInfo prop = typeof(ServiceAttributes).GetProperty(kv.Key);
                    object value = prop.GetValue(service.Attributes);
                    prop.SetValue(service.Attributes, kv.Value);
                }
                else
                {
                    if (!service.Attributes.Vars.ContainsKey(kv.Key) && Debug)
                    {
                        Logger.LogInformation("Skiping " + kv.Key + ", doesn't exist on " + service.GetIcingaName());
                        continue;
                    }
                    outVars.Vars[kv.Key] = kv.Value;
                }
            }
            var result = await API.UpdateServiceAsync(service.HostName, service.ServiceName, outVars);
            return result.RootElement.ToString().Contains("200");
        }

        public async Task<List<Service>> TryGetHostServices(string host)
        {
            try
            {
                return await API.SearchServiceAsync("service.host_name==\"" + host + "\"");
            }
            catch
            {
                return null;
            }
        }
        
        public async Task<Service> TryGetServiceAsync(string host, string service)
        {
            try
            {
                return await API.GetServiceAsync(host, service);
            }
            catch (IcingaObjectNotFoundException ex)
            {
                Logger.LogError(host + "!" + service + ": " + ex.ServerResponse);
                return null;
            }
        }

        private bool Init()
        {
            try
            {
                var icingaConfig = new IcingaConfig
                {
                    Address = Configuration["host"],
                    User = Configuration["username"],
                    Password = Configuration["password"],
                    RoutingKey = Configuration["routing_key"]
                };
                var handler = new HttpClientHandler
                {
                    ClientCertificateOptions = ClientCertificateOption.Manual,
                    ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) => { return true; }//do this when creating http client to skip cert valdation
                };
                var httpClient = new HttpClient(handler);
                var logger = new ConsoleLogger(Debug);
                var icingaClient = new IcingaApiClient(httpClient, logger, icingaConfig);
                API = icingaClient; 
                return true;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex.ToString());
                return false;
            }
        }
        #endregion
    }
}
