using ART.SymphonyClient.MessageAbstraction;
using ART.SymphonyClient.Models;
using ART.SymphonyClient.SymphonyApi;
using ART.SymphonyClient;
using DanskeBank.IcingaApiClient;
using Newtonsoft.Json.Serialization;
using Newtonsoft.Json;
using StackExchange.Redis;
using SuperFlySharp.Data.Container;
using SuperFlySharp.Data;
using SuperFlySharp.Date;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Net;
using System.Reactive.Linq;
using System.Reactive;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Web;
using System;
using Microsoft.Extensions.Configuration;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using System.Reflection;

namespace QRASymphonyBot
{
    class SymphonyBot
    {
        #region Members
        //private
        private Client SymphonyClient;
        protected readonly Microsoft.Extensions.Logging.ILogger Log;
        private String BuserFilter = "";
        protected String BotTag = "!Q";
        private readonly String BotMention = "@Qrabot";
        private readonly String BotInReply = "In reply to:Qrabot";
        private List<String> ElevatedUsers = new List<string>();
        private readonly String TimeStampFormat = "yyyy/MM/dd HH:mm:ss.fff";//"MM/dd/yyyy hh:mm:ss.fff tt";

        //Robot function members
        private readonly Func<string, string, List<string>> NotImplementedFunc = (string x, string u) => { return new List<string>() { "NOT YET IMPLEMENTED" }; };
        protected Dictionary<String, String> RobotFuncs = new Dictionary<String, String>();
        protected Dictionary<String, List<string>> RobotFuncsHelp = new Dictionary<String, List<string>>();
        protected Dictionary<String, String> RobotFuncsExamples = new Dictionary<String, String>();
        protected List<String> RobotFuncsProtected = new List<string>();
        protected List<String> RobotFuncsRequiresTime = new List<string>();
        protected List<String> RobotFuncsRequiresStreamId = new List<string>();
        protected List<String> RobotFuncsRequiresUserId = new List<string>();
        private readonly List<String> RobotGreetings = new List<String>() { "HELLO", "HEY", "HEJ", "HI", "HOLA" };
        private readonly List<String> RobotFarewells = new List<String>() { "FAREWELL", "BYE", "C YA", "C YOU", "CYA", "CYOU", "GOODBYE" };
        private Dictionary<String, List<string>> Excuses = new Dictionary<String, List<string>>();
        private List<String> NoUserReplies = new List<string>();

        //HTTP relevant members
        static private readonly List<string> skipMarks = new List<string>() {
            "<i>", "<b>", "<br>", "<li>","<a>","<td>","<h>", "<table>", "<body>",
            "<i/>", "<b/>", "<br/>", "<li/>","<a/>","<td/>","<h/>", "<table/>", "<body/>",
            "</i>", "</b>", "</br>", "</li>", "</a>", "</td>", "</h>", "</table>", "</body>",
            "<mention" };
        #endregion

        public SymphonyBot(IConfiguration configuration, Microsoft.Extensions.Logging.ILogger logger)
        {
            Log = logger;
            Init(configuration);
        }

        /// <summary>
        /// Destructor
        /// </summary>
        ~SymphonyBot()
        {
            Log.LogInformation("Calling SymphonyBot destructor.");
        }

        internal void Init(IConfiguration configuration)
        {
            Excuses = configuration.GetSection("EXCUSES").GetChildren().ToDictionary(x => x.Key, x => configuration.GetSection("EXCUSES").GetSection(x.Key).GetChildren().ToList().Select(k => k.Value).ToList());
            NoUserReplies = configuration.GetSection("EXCUSES:NOUSER").GetChildren().Select(v => v.Value).ToList();
#if DEBUG
            bool debug = true;
#else
            bool debug = false;
#endif
            //Initialize Symphony Bot communication
            //Symphony settings container
            var settings = new SettingsContainer
            {
                BotPrivateKeyPath = configuration["SYMPHONY:BotPrivateKeyPath"],
                BotPrivateKeyName = configuration["SYMPHONY:BotPrivateKeyName"],
                BotUsername = configuration["SYMPHONY:BotUsername"],
                PodHost = configuration["SYMPHONY:PodHost"]
            };
            //Setup proxy so we can access the symphony API programatically
            var proxySettings = new ProxySettingsContainer
            {
                ProxyUsername = configuration["SYMPHONY:ProxyUsername"],
                ProxyPassword = configuration["SYMPHONY:ProxyPassword"],
                ProxyType = ProxyEnum.Ntlm,
                ProxyUrl = configuration["SYMPHONY:ProxyUrl" + (debug ? "Debug" : "")],
            };
            //Initialize Symphony client
            SymphonyClient = new Client(settings, proxySettings);
            SubscribeToSymphonyEvents();
            Log.LogInformation("SymphonyBot initialized successfully!");
        }

        #region Helpers
        /// <summary>
        /// Add a list of elevated users for validatino of access.
        /// </summary>
        /// <param name="elevatedUsers"></param>
        public void AddElevatedUsers(List<String> elevatedUsers)
        {
            ElevatedUsers = elevatedUsers;
        }

        /// <summary>
        /// Set user based filter on the incoming Symphony messages.
        /// </summary>
        /// <param name="buser">Domain-less B-name.</param>
        public void SetSymphonyUserFilter(String buser)
        {
            BuserFilter = buser;
        }

        /// <summary>
        /// Set to what tag i the chat the bot should react.
        /// </summary>
        /// <param name="botTag"></param>
        public void SetBotTag(string botTag)
        {
            BotTag = botTag;
        }

        /// <summary>
        /// Create, based on "excuses.json", a reply when something goes wrong.
        /// </summary>
        /// <param name="user">Who to address the message to.</param>
        /// <param name="matchThis">Try to match this reply.</param>
        /// <returns></returns>
        internal String GetRandomReply(String user, String matchThis = "")
        {
            Random r = new Random();
            String Greet = "";
            if (user != "")
            {
                int rGreet = r.Next(0, Excuses["LEVEL1"].Count - 1);
                Greet = Excuses["LEVEL1"][rGreet];
            }
            String ReplyId = "UNKNOWN";
            if (matchThis != "")
            {
                ReplyId = Excuses.Where(e => Regex.IsMatch(matchThis.ToUpper(), "\\b" + e.Key + "\\b")).Select(e => e.Key).FirstOrDefault();
                if (ReplyId == default(String)) ReplyId = "SYNTAX";
                if (NoUserReplies.Contains(ReplyId)) user = "";
            }
            r = new Random();
            int rReply = Excuses[ReplyId].Count > 1 ? r.Next(0, Excuses[ReplyId].Count - 1) : 0;
            String Reply = Excuses[ReplyId][rReply];
            return (user != "" ? (Greet + ", " + user + ", ") : "") + Reply;
        }

        /// <summary>
        /// Strip user message into recognized funcitons, and variables for them, if possible.
        /// </summary>
        /// <param name="msg"></param>
        /// <returns></returns>
        private Tuple<String, String> ParseMessageIntoFunc(String msg)
        {
            var approvedFunc = RobotFuncs.Where(kv => Regex.IsMatch(msg.ToUpper(), "\\b" + kv.Key + "\\b")).Select(kv => kv.Key).ToList();
            if (approvedFunc.Count() == 0)
                return new Tuple<String, String>("", "");
            if (approvedFunc.Count > 1) //might have multiple function matches. use the one mentioned first in the msg.
            {
                int idx = msg.Length + 1;
                int keep = 0;
                foreach (var f in approvedFunc)
                    if (msg.ToUpper().IndexOf(f) < idx)
                    {
                        idx = msg.ToUpper().IndexOf(f);
                        keep = approvedFunc.IndexOf(f);
                    }
                approvedFunc = new List<string>(){approvedFunc[keep] };
            }
            string fullfunc = msg.Substring(msg.ToUpper().IndexOf(approvedFunc[0]));
            bool isComplexFunc = fullfunc.Contains("(") && fullfunc.Contains(")");
            var varsStart = fullfunc.IndexOf("(");
            var varsEnd = isComplexFunc ? fullfunc.LastIndexOf(")")+1 : fullfunc.IndexOfAny("?!. ,;:".ToCharArray());
            if (varsEnd < 0) varsEnd = fullfunc.Length;
            fullfunc = fullfunc.Substring(0, varsEnd);
            var func = isComplexFunc ? fullfunc.Substring(0, varsStart) : fullfunc;
            var vars = isComplexFunc ? fullfunc.Substring(varsStart + 1, varsEnd - varsStart - 2).Trim() : "";
            return new Tuple<String, String>(func, vars);
        }
        #endregion

        #region Symphony Methods
        /// <summary>
        /// Get StreamIds of allthe rooms where QraBot is present.
        /// </summary>
        /// <returns></returns>
        protected string GetRoomName(string streamId)
        {
            List<IStream> rooms = SymphonyClient.ListStreams(StreamType.Room).Result.ToList();
            var room = rooms.Where(r => r.StreamId == streamId).ToList();
            if (room.Count > 0)
                return (room as IRoom).RoomDto.name;
            else
                return "";
        }

        /// <summary>
        /// Return Symphony details for B-user provided in the input.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        protected List<String> GetUser(String user)
        {

            try
            {
                var someUser = SymphonyClient.GetUserFromUsername(user).Result;
                return GetUserHelper(someUser);
            }
            catch
            {
                return new List<string>() { $"Couldn't find {user} user." };
            }

        }

        /// <summary>
        /// Get user based on Symphony user id.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        protected List<String> GetUser(long user)
        {

            try
            {
                var someUser = SymphonyClient.GetUserFromUserId(user).Result;
                return GetUserHelper(someUser);
            }
            catch
            {
                return new List<string>() { $"Couldn't find {user} user." };
            }

        }

        /// <summary>
        /// Convert Symphony User object into a printable list.
        /// </summary>
        /// <param name="someUser"></param>
        /// <returns></returns>
        protected List<String> GetUserHelper(IUser someUser)
        {
            List<String> outputs = new List<string>();
            outputs.Add("Full name: <i>" + someUser.UserDto.DisplayName + "</i>");
            outputs.Add("Email: <i>" + someUser.UserDto.Email + "</i>");
            outputs.Add("Username: <i>" + someUser.UserDto.Username + "</i>");
            outputs.Add("Symphony ID: <i>" + someUser.UserDto.UserId.ToString() + "</i>");
            return outputs;
        }

        /// <summary>
        /// Override SymphonyBot message handler.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="messageText"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        private List<String> HandleRoomTextIntoList(User user, String messageText, IUserMessage message)
        {
            messageText = messageText.Trim();
            var msgVars = messageText.ToUpper().Split(" ");
            if (messageText.StartsWith(BotInReply))
                return null;
            if (message.IAmMentioned())
                messageText = messageText.Replace(BotMention, "").Trim();
            else if ((msgVars[0].Length >= BotTag.Length && msgVars[0].Substring(0, BotTag.Length) == BotTag))
                messageText = messageText.Substring(2).Trim();
            else
                return null;
            return MessageHandler(user, messageText, message);
        }

        /// <summary>
        /// Override SymphonyBot message handler.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="messageText"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        private List<String> HandleImTextIntoList(User user, String messageText, IUserMessage message)
        {
            if (messageText.StartsWith(BotInReply))
                return null;
            if (message.IAmMentioned())
                messageText = messageText.Replace(BotMention, "");
            messageText = messageText.Trim();
            if (messageText.Length > BotTag.Length && messageText.ToUpper().Substring(0, BotTag.Length) == BotTag)
                messageText = messageText.Substring(BotTag.Length).Trim();
            return MessageHandler(user, messageText, message);
        }

        /// <summary>
        /// Override SymphonyBot message handler.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="messageText"></param>
        /// <param name="message">IUserMessage object.</param>
        /// <returns></returns>
        private List<String> MessageHandler(User user, String messageText, IUserMessage message)
        {
            List<String> messageOut;
            bool approvedFunc = false;
            String func = messageText;
            DateTime t0 = DateTime.Now;
            try
            {
                //process msg
                var parsed = ParseMessageIntoFunc(messageText);

                //Handle func
                if (parsed.Item1 != "")
                {
                    approvedFunc = true;
                    func = parsed.Item1;
                    var vars = parsed.Item2;
                    //return new List<string>() { "Parsed into: " + func + "(" + vars + ")" };
                    if (RobotFuncsProtected.Contains(func.ToUpper()))
                    {
                        if (!ElevatedUsers.Contains(user.UserDto.Username))
                            return new List<string>() { func.ToUpper() + " requires elevated rights, and " + user.UserDto.DisplayName + " lacks those. Consider applying for XX-YY-ZZ." };
                    }
                    if (RobotFuncsRequiresTime.Contains(func.ToUpper()))
                        vars += "#time0=" + t0.ToString(TimeStampFormat) + "#timeformat=" + TimeStampFormat;
                    if (RobotFuncsRequiresStreamId.Contains(func.ToUpper()))
                        vars += "#streamId=" + message.StreamId;
                    if (RobotFuncsRequiresUserId.Contains(func.ToUpper()))
                        vars += "#thisuid=" + user.UserDto.UserId;//add requesting userid to inputs TODO: should remove it if already there.

                    if (RobotFuncs.ContainsKey(func.ToUpper()))
                    {
                        MethodInfo theMethod = this.GetType().GetMethod(RobotFuncs[func.ToUpper()], BindingFlags.NonPublic | BindingFlags.Instance);
                        messageOut = (List<string>) theMethod.Invoke(this, new object[] { vars, user.UserDto.Username });
                    }
                    else
                        messageOut = new List<string>() { "Unknown func: \"" + func + "\". Call \"" + BotTag + " HELP\" to read what i can do." };
                }
                else
                {
                    var greet = RobotGreetings.Where(g => Regex.IsMatch(func.ToUpper(), "\\b" + g + "\\b")).ToList().Count() > 0;
                    var bye = RobotFarewells.Where(b => Regex.IsMatch(func.ToUpper(), "\\b" + b + "\\b")).ToList().Count() > 0;
                    if (func.ToUpper().Contains("HELLO THERE"))
                        messageOut = new List<string>() { "General Kenobi..." };
                    else if (greet)
                        messageOut = new List<string>() { "Howdy, " + user.UserDto.DisplayName + "." };
                    else if (bye)
                        messageOut = new List<string>() { "Farewell, " + user.UserDto.DisplayName + "!" };
                    else if (func == "")
                        messageOut = new List<string>() { "Yes, " + user.UserDto.DisplayName + "? What can I do for you?" };
                    else
                    {
                        var reply = GetRandomReply(user.UserDto.DisplayName, func);
                        messageOut = new List<string>() { reply == "" ? ("Unknown func: \"" + func + "\". Call \"" + BotTag + " HELP\" to read what i can do.") : reply };
                    };
                }
            }
            catch (Exception ex)
            {
                messageOut = new List<string>() { GetRandomReply(user.UserDto.DisplayName, approvedFunc ? "SYNTAX" : "UNKNOWN") };
                if (approvedFunc && RobotFuncsHelp.ContainsKey(func.ToUpper()) && RobotFuncsExamples.ContainsKey(func.ToUpper()))
                {
                    messageOut.Add("<hr/><b>Check your syntax against examples:</b>");
                    messageOut.Add(RobotFuncsExamples[func.ToUpper()]);
                }
                else
                    messageOut.Add("<hr/><b>Couldn't identify the function. Guess was: " + func.ToUpper() + "</b>");
                Log.LogError(ex, "SymphonyBot failed when processing user message.");
            }
            return messageOut;
        }

        /// <summary>
        /// Format string into an HTML encoded string, with relevant escape characters.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        private string FormatToHtmlString(string message)
        {
            bool skipEncoding = skipMarks.Select(m => message.Contains(m)).Any(r => r == true);
            if (skipEncoding)
                return message;
            else
            {
                if (HttpUtility.HtmlDecode(message) != message)//prevent double encoding.
                    return message;
                else
                    return HttpUtility.HtmlEncode(message);
            }
        }

        /// <summary>
        /// Send message to symphony
        /// </summary>
        /// <param name="streamId">Room id</param>
        /// <param name="messages">List of messages.</param>
        /// <returns></returns>
        protected async Task SendAsHtmlStream(String streamId, List<String> messages)
        {//https://renderer-tool.app.symphony.com/
            var isHtmlTable = messages.Select(m => m.Contains("</td>") || m.Contains("</tr")).Any(r => r == true);
            messages = messages.Select(m => FormatToHtmlString(m)).ToList();
            string html = $@"<messageML><p>{String.Join(isHtmlTable ? "" : "<br/>", messages)}</p></messageML>";
            var messageOut = HtmlMessage.CreateMessage(html, new { name = "message" });
            try
            {
                await SymphonyClient.SendMessageToStream(streamId, messageOut);
            }
            catch (Exception ex)
            {
                Log.LogError(ex.Message + "\n" + ((SymphonyApiException)ex.InnerException).Response);
            }
        }

        /// <summary>
        /// Tell the bot how to handle direct messages, room messages, etc.
        /// </summary>
        private void SubscribeToSymphonyEvents()
        {

            //Subscribe to messages
            SymphonyClient.ImSubscribe(async (message) =>
            {//https://developers.symphony.com/symphony-developer/docs/messagemlv2#taxonomy-mention
                var lastMessage = message.Message.FormatToString().Replace("<messageML>", "").Replace("</messageML>", "");
                lastMessage = HttpUtility.HtmlDecode(lastMessage);
                if (BuserFilter != "" && message.User.UserDto.Username != BuserFilter)
                    return;
                var newMessage = HandleImTextIntoList(message.User as User, lastMessage, message);
                if (newMessage != null)
                    await SendAsHtmlStream(message.StreamId, newMessage);
            });

            SymphonyClient.MessageSentInRoomSubscribe(async (message) =>
            {
                var lastMessage = message.Message.FormatToString().Replace("<messageML>", "").Replace("</messageML>", "");
                lastMessage = HttpUtility.HtmlDecode(lastMessage);
                if (BuserFilter != "" && message.User.UserDto.Username != BuserFilter)
                    return;
                lastMessage = HttpUtility.HtmlDecode(lastMessage);
                var newMessage = HandleRoomTextIntoList(message.User as User, lastMessage, message);
                if (newMessage != null)
                    await SendAsHtmlStream(message.StreamId, newMessage);
            });

            SymphonyClient.WhenAddedToRoom(async (room) =>
            {
                var newMessage = new List<String>() { "It is I, Qrabot!", "Call \"!Q <i>query</i>\" (case insensitive) to get my attention.", "Call \"!Q HELP\" to read what i can do." };
                if (newMessage != null)
                    await SendAsHtmlStream(room.StreamId, newMessage);
            });
        }

        /// <summary>
        /// Start Symphony polling.
        /// </summary>
        /// <returns></returns>
        public async Task RunClient()
        {
            //Authenticate the Bot. This is call is needed to interact with symphony.
            await SymphonyClient.Authenticate();

            //Start continously polling symphony for new events related to the bot. This call is not needed if you don't want to react to events
            Log.LogInformation("Starting Symphony polling.");
            await SymphonyClient.Run(CancellationToken.None);
        }
        #endregion
    }

    class SymphonyIcingaBot : SymphonyBot
    {
        #region Members
        //private
        private static PowerShellRunner PS;

        private DateTime DefaultAnchor;
        private String DefaultAnchorStr;
        private readonly TimeSpan BatchCutOff = new TimeSpan(0, 13, 0, 0, 0);
        private readonly Func<string, string, List<string>> NotImplementedFunc = (string x, string u) => { return new List<string>() { "NOT YET IMPLEMENTED" }; };

        //Batch silencing
        private String BatchSilenceFile;
        private readonly String BatchSilenceExePath = "\\\\danskenet.net\\markets\\Superfly\\Executables\\ProductionAnalytics\\current.txt";

        //HTTP relevant members
        private static HttpClient Http;
        private static HttpClient HttpWithProxy;
        private static HttpClientHandler HttpProxyHandler;

        //Members for running tasks on the side.
        private Timer Timer;
        private HashSet<Tuple<string, string>> CurrentTasks = new HashSet<Tuple<string, string>>();

        //Jira members
        private AuthenticationHeaderValue JiraAuthorization;
        private String JiraURLBase;
        private String JiraParentTicket;
        private readonly List<String> JiraFields = new List<string>() { "key", "summary", "description", "comment", "labels", "assignee" };

        //VictorOps members
        private String VictorOpsURLBase;
        private Dictionary<String, String> VictorOpsHeader = new Dictionary<String, String>();
        private Dictionary<String, String> VictorOpsQRATeams = new Dictionary<String, String>();
        private Dictionary<String, Dictionary<String, List<String>>> VictorOpsPolicies = new Dictionary<string, Dictionary<String, List<String>>>();
        private Dictionary<String, String> VictorOpsAllTeams = new Dictionary<string, string>();

        //RtData aka Sonic members
        private IRtDataProvider RtDataSource;
        private Dictionary<String, IDictionary<string, string>> RtDataDict = new Dictionary<String, IDictionary<String, String>>();
        private IObservable<IRtTickOut<IRtRecord>> RtObserveFeedsTick;
        private IDisposable RtDataSubscription;
        private String RtDataIDToObserve = "QuantWatchErrors.*";

        //Icinga members
        private Dictionary<String, IcingaClient> IcingaClients = new Dictionary<String, IcingaClient>();
        private readonly List<String> IcingaSupportedEnvs = new List<string> { "TEST", "PROD" };
        private String IcingaDefaultEnv = "PROD";
        private readonly Dictionary<int, string> IcingaStatesMap = new Dictionary<int, string>() { { 0, "OK" }, { 1, "WARNING" }, { 2, "ERROR" }, { 3, "UNKNOWN" }, { 99, "PENDING" } };
        private String IcingaDefaultHost, IcingaPreviousDefaultHost;
        private readonly String IcingaDefaultPollingHost = "QRA_Intraday";
        private Dictionary<String, Dictionary<String, String>> IcingaPollingSubscriptionFilters = new Dictionary<string, Dictionary<string, string>>();
        private Dictionary<String, List<String>> IcingaPollingSubscriptionList = new Dictionary<string, List<string>>();
        private Dictionary<String, Tuple<DateTime, DateTime>> IcingaPollingLastUpdate = new Dictionary<String, Tuple<DateTime, DateTime>>();
        private readonly TimeSpan IcingaPollingFlickerLimit = new TimeSpan(0, 0, 5, 0, 0);
        private readonly int IcingaPollingFrequency = 1;
        private readonly int IcingaPollingFloodLimit = 1;
        private readonly string IcingaPollingContName = "IcingaPollingSubscriptionFilters";
        private string IcingaPollingContUsage = "RT";
        private readonly string IcingaPollingBatchFlag = "$B$";
        #endregion

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="configuration"></param>
        /// <param name="logger"></param>
        /// <param name="rtDataSource"></param>
        public SymphonyIcingaBot(IConfiguration configuration, Microsoft.Extensions.Logging.ILogger logger, IRtDataProvider rtDataSource) : base(configuration, logger)
        {
            RtDataSource = rtDataSource;
            PS = new PowerShellRunner(configuration["GLOBAL:credentials"]);
            Init(configuration);
        }

        /// <summary>
        /// Destructor
        /// </summary>
        ~SymphonyIcingaBot()
        {
            Log.LogInformation("Calling SymphonyIcingaBot destructor.");
            RtDataSubscription.Dispose();
        }

        internal new void Init(IConfiguration configuration)
        {
#if DEBUG
            bool debug = true;
#else
            bool debug = false;
#endif
            //Initialize Symphony Bot communication
            RobotFuncsProtected = new List<string>() { "OK", "UPDATE", "SILENCE", "TEST", "HANDOVER", "ALERT" };
            RobotFuncsRequiresTime = new List<string>() { "PING" };
            RobotFuncsRequiresStreamId = new List<string>() { "OK", "IPOLL", "RERUN", "TEST", "UNITRISK","THROWBLAME" };
            RobotFuncsRequiresUserId = new List<string>() { "UPDATE", "PING", "WHOAMI"};

            //Initialize anchor
            AdjustAnchor();

            //Set BatchSilenceFile
            BatchSilenceFile = Path.Join(configuration["GLOBAL:batchSilencePath"], configuration["GLOBAL:batchSilenceFile"]);

            //Initialize Icinga envs
            foreach (var env in IcingaSupportedEnvs)
                IcingaClients[env] = new IcingaClient(configuration.GetSection("ICINGA" + env), env, Log, debug);

            //Proxy http
            SetupProxyHttpHandler(configuration["GLOBAL:ProxyUrl" + (debug ? "Debug" : "")]);

            //Nonproxy http
            SetupHttpHandler();

            //Set up sonic listener
            InitializeRtTickFeeds();

            //Set up Icinga polling
            StartIcignaPolling(IcingaPollingFrequency);

            //Set Jira access
            JiraParentTicket = configuration["JIRA:batchParentTicket"];
            AddJiraCredentials(configuration["JIRA:url"], configuration["GLOBAL:credentials"]);

            //Set VOPS groups
            SetupVictorOps(configuration["VOPS:url"], configuration["VOPS:ApiId"], configuration["VOPS:ApiKey"], configuration.GetSection("VOPSTEAMS"));

            //Symphony chat bot functions
            RobotFuncs = configuration.GetSection("ROBOTFUNCS").GetChildren().ToDictionary(x => x.Key, x => x.Value);

            //Symphony chat bot help.
            RobotFuncsHelp = configuration.GetSection("ROBOTHELP").GetChildren().ToDictionary(x => x.Key, x => configuration.GetSection("ROBOTHELP").GetSection(x.Key).GetChildren().ToList().Select(k => k.Value).ToList());

            //Symphony chat bot examples
            RobotFuncsExamples = configuration.GetSection("ROBOTEXAMPLES").GetChildren().ToDictionary(x => x.Key, x => x.Value);
        }

        #region Helpers
        /// <summary>
        /// Allow the Sonid feed ID to be changed from the outside.
        /// </summary>
        /// <param name="newId"></param>
        public void SetRtDataId(string newId)
        {
            RtDataIDToObserve = newId;
        }

        /// <summary>
        /// Periodically poll all services from DefaultHost in DefaultEnv environment.
        /// </summary>
        /// <param name="frequency"></param>
        internal void StartIcignaPolling(int frequency)
        {
            var freqTimeSpan = TimeSpan.FromMinutes(frequency);
            var timerStart = TimeSpan.FromSeconds(10);
#if DEBUG
            IcingaPollingContUsage = "TEST";
            IcingaDefaultEnv = "TEST";
#endif
            LoadIcingaPolling(IcingaPollingContName, IcingaPollingContUsage);
            Timer = new System.Threading.Timer((e) =>
            {
                PollIcinga();
            }, null, timerStart, freqTimeSpan);
        }

        /// <summary>
        /// Gather Icinga services in Critical state, and inform the relevant rooms about it, based on the room specific filters.
        /// </summary>
        internal void PollIcinga()
        {
            //Make sure we use the right batch anchor after 1PM
            if (DateTime.Now.Hour >= BatchCutOff.Hours) AdjustAnchor();
            //GC.Collect();

            //Poll
            var IcingaPollingServices = IcingaClients[IcingaDefaultEnv].TryGetHostServices(IcingaDefaultPollingHost).Result;
            var IcingaBatchPollingServices = IcingaClients[IcingaDefaultEnv].TryGetHostServices(IcingaDefaultHost).Result;

            //Intraday
            if (IcingaPollingServices != null)
            {
                var filter = IcingaPollingSubscriptionFilters.Where(kv => !kv.Key.Contains("#" + IcingaPollingBatchFlag)).ToDictionary(kv => kv.Key, kv => kv.Value);
                try
                {
                    PollIcingaHelper(IcingaPollingServices, filter);
                }
                catch (Exception ex)
                {
                    Log.LogError(ex, "PollIcingaHelper failed for Intraday polling..");
                }
            }
            //EOD Batch
            if (IcingaBatchPollingServices != null)
            {
                var filter = IcingaPollingSubscriptionFilters.Where(kv => kv.Key.Contains("#" + IcingaPollingBatchFlag)).ToDictionary(kv => kv.Key, kv => kv.Value);
                try
                {
                    PollIcingaHelper(IcingaBatchPollingServices, filter);
                }
                catch (Exception ex)
                {
                    Log.LogError(ex, "PollIcingaHelper failed for EOD polling.");
                }
            }
        }

        /// <summary>
        /// For specific list of services and given the fitlers per room, inform rooms about the relevant issues.
        /// </summary>
        /// <param name="allServices">List of services</param>
        /// <param name="icingaPollingFilters">Dict of rooms and filters relevant for them.</param>
        internal void PollIcingaHelper(List<Service> allServices, Dictionary<string, Dictionary<string, string>> icingaPollingFilters)
        {
            var servicesInRed = allServices.Where(s => (s.RuntimeAttributes.LastCheckResult is null ? 99 : Int32.Parse(s.RuntimeAttributes.LastCheckResult["state"].ToString().Replace(".0", ""))) == 2).ToList();
            var redNames = servicesInRed.Select(s => s.GetIcingaName()).ToList();
            foreach (var kv in icingaPollingFilters)
            {
                var getTimeLimit = kv.Key.Split("@").ToList();
                
                var getTagAndRoom = getTimeLimit[0].Split("#").ToList();
                var tag = getTagAndRoom.Count > 1 ? getTagAndRoom[1] : "";
                var room = getTagAndRoom[0];
                var filterKey = kv.Key;
                var filter = kv.Value.Where(k => k.Key != "").ToList();
                if (getTimeLimit.Count > 1)
                {//exit if time is set, and it's past that time. Only works as "stoppage" time.
                    var timeLimits = getTimeLimit[1].Split("-");
                    DateTime start = DateTime.Parse(timeLimits[0], System.Globalization.CultureInfo.CurrentCulture);
                    DateTime stop = DateTime.Parse(timeLimits[1], System.Globalization.CultureInfo.CurrentCulture);
                    if (DateTime.Now > stop || DateTime.Now < start)
                    {
                        if (IcingaPollingSubscriptionList.ContainsKey(filterKey) && IcingaPollingSubscriptionList[filterKey].Count()>0)
                            IcingaPollingSubscriptionList[filterKey] = new List<string>(); //Remove old services, since they will no longer be in scope, when Now>start.
                        continue;
                    }
                }
                if (!IcingaPollingSubscriptionList.ContainsKey(filterKey)) IcingaPollingSubscriptionList[filterKey] = new List<string>();
                var NewRedServices = servicesInRed.Where(s => !IcingaPollingSubscriptionList[filterKey].Contains(s.GetIcingaName())).ToList();
                var CurrentRedServicesNames = servicesInRed.Where(s => IcingaPollingSubscriptionList[filterKey].Contains(s.GetIcingaName())).Select(s => s.GetIcingaName()).ToList();
                var ResolvedServices = allServices.Where(s => (s.RuntimeAttributes.LastCheckResult is null ? 99 : Int32.Parse(s.RuntimeAttributes.LastCheckResult["state"].ToString().Replace(".0", ""))) < 2
                                                                && !redNames.Contains(s.GetIcingaName())
                                                                && IcingaPollingSubscriptionList[filterKey].Contains(s.GetIcingaName())).ToList();
                //remove if green now
                IcingaPollingSubscriptionList[filterKey] = CurrentRedServicesNames.Where(s => redNames.Contains(s)).ToList();
                IcingaPollingSubscriptionList[filterKey].AddRange(NewRedServices.Select(s => s.GetIcingaName()).ToList());
                
                //Check if anything new should be posted
                if (NewRedServices.Count > 0)
                {
                    //Prepare services
                    //exclusive filters
                    NewRedServices = PollIcingaFilterApply(filter.Where(kv => kv.Value.StartsWith("-")).ToList(), NewRedServices);
                    //inclusive filters
                    NewRedServices = PollIcingaFilterApply(filter.Where(kv => !kv.Value.StartsWith("-")).ToList(), NewRedServices);
                    //check if reported resolved recently, then skip it.
                    var snapNow = DateTime.Now;
                    var NotRecentlyResolved = NewRedServices.Where(s => !IcingaPollingLastUpdate.ContainsKey(s.ServiceName)
                                                                   || (snapNow - IcingaPollingLastUpdate[s.ServiceName].Item2 >= IcingaPollingFlickerLimit)).ToList();
                    NewRedServices = NotRecentlyResolved;
                    //Message room with status of those relevantServices
                    if (NewRedServices.Count() > IcingaPollingFloodLimit)
                    {
                        var messageOut = new List<string>
                        {
                            (tag != "" ? "<hash tag=\"" + tag + "\"/> " : "") + "<b>!!!!!! " + NewRedServices.Count().ToString() + " jobs failed!!!!!!</b>",
                            "From Icinga host: <i>" + NewRedServices.First().HostName + "</i>"
                        };
                        messageOut.AddRange(NewRedServices.Select(s => IcignaServiceToStatus(s, true, false, true).First()).ToList());
                        _ = SendAsHtmlStream(room, messageOut);
                    }
                    else
                    {
                            foreach (var service in NewRedServices)
                        {
                            var messageOut = IcignaServiceToStatus(service, true);
                            if (tag != "")
                                messageOut[0] = "<hash tag=\"" + tag + "\"/> " + messageOut[0];
                            _ = SendAsHtmlStream(room, messageOut);
                        }
                    }
                    //Keep details about when it was added
                    foreach (var s in NewRedServices)
                        IcingaPollingLastUpdate[s.ServiceName] = new Tuple<DateTime, DateTime>(snapNow, IcingaPollingLastUpdate.ContainsKey(s.ServiceName) ? IcingaPollingLastUpdate[s.ServiceName].Item2 : DateTime.MinValue);
                }
                if (ResolvedServices.Count > 0)
                {
                    //Prepare services
                    //exclusive filters
                    ResolvedServices = PollIcingaFilterApply(filter.Where(kv => kv.Value.StartsWith("-")).ToList(), ResolvedServices);
                    //inclusive filters
                    ResolvedServices = PollIcingaFilterApply(filter.Where(kv => !kv.Value.StartsWith("-")).ToList(), ResolvedServices);
                    //check if reported as new recently, then skip it.
                    var snapNow = DateTime.Now;
                    var NotRecentlyReported = ResolvedServices.Where(s => !IcingaPollingLastUpdate.ContainsKey(s.ServiceName)
                                                                   || (snapNow - IcingaPollingLastUpdate[s.ServiceName].Item1 >= IcingaPollingFlickerLimit)).ToList();
                    ResolvedServices = NotRecentlyReported;
                    if (ResolvedServices.Count > 0)
                    {
                        //Message what was resolved
                        var messageOut = new List<string>
                        {
                            (tag != "" ? "<hash tag=\"" + tag + "\"/> " : "") + "<b>**** Resolved " + ResolvedServices.Count().ToString() + " jobs **** </b>",
                            "From Icinga host: <i>" + ResolvedServices.First().HostName + "</i>"
                        };
                        messageOut.AddRange(ResolvedServices.Select(s => IcignaServiceToStatus(s, true, false, true).First()).ToList());
                        _ = SendAsHtmlStream(room, messageOut);
                        //Keep details about when it was resolved
                        foreach (var s in ResolvedServices)
                            IcingaPollingLastUpdate[s.ServiceName] = new Tuple<DateTime, DateTime>(IcingaPollingLastUpdate.ContainsKey(s.ServiceName) ? IcingaPollingLastUpdate[s.ServiceName].Item1 : DateTime.MinValue, snapNow);
                    }
                }
            }
        }

        /// <summary>
        /// Apply fitlers from "filter" to a list of services.
        /// </summary>
        /// <param name="filter">Icinga field filter.</param>
        /// <param name="services">Icinga services.</param>
        /// <returns></returns>
        internal List<Service> PollIcingaFilterApply(List<KeyValuePair<string, string>> filter, List<Service> services)
        {
            //Prepare messages
            var outServices = services;
            foreach (var kv2 in filter)
            {
                var key = kv2.Key.ToUpper();
                bool exclFilter = kv2.Value.StartsWith("-");
                var val = kv2.Value.ToUpper(); 
                
                List<Service> RemainingIcingaServices = new List<Service>();
                if (exclFilter)
                {
                    val = val.Substring(1);
                    Service[] array = new Service[outServices.Count];
                    outServices.CopyTo(array);
                    RemainingIcingaServices = array.ToList();
                }
                foreach (var s in outServices)
                {
                    var data = ParseIcingaAttributes(s.Attributes);
                    if (key == "SERVICEGROUP")
                    {
                        var groups = (data["GROUPS"] as List<string>).Select(v => v.ToUpper()).ToList();
                        if (groups.Contains(val))
                        {
                            if (exclFilter) RemainingIcingaServices.Remove(s);
                            else RemainingIcingaServices.Add(s);
                        }
                    }
                    else
                    {
                        if (!data.ContainsKey(key)) continue;
                        if (data[key].ToString().ToUpper() == val)
                        {
                            if (exclFilter) RemainingIcingaServices.Remove(s);
                            else RemainingIcingaServices.Add(s);
                        }
                    }
                }
                outServices = RemainingIcingaServices;
            }
            return outServices;
        }

        /// <summary>
        /// Attempt finding "service" on "host" in Icinga "env" environment. Ignore case of the service name.
        /// </summary>
        /// <param name="env">Icinga environment.</param>
        /// <param name="host">Icinga host name.</param>
        /// <param name="service">Service name, potentialyl case insensitive.</param>
        /// <returns></returns>
        internal Service TryGetService(string env, string host, string service)
        {
            var IcingaService = IcingaClients[env].TryGetServiceAsync(host, service).Result;
            if (IcingaService is null)
            {
                //try in all host servcies, by case insensitive name
                var IcingaServices = IcingaClients[env].TryGetHostServices(host).Result;
                var currentServices = IcingaServices.Where(s => s.GetIcingaName().ToUpper() == host.ToUpper() + "!" + service.ToUpper()).ToList();
                IcingaService = currentServices.Count > 0 ? currentServices.First() : null;
            }
            return IcingaService;
        }

        /// <summary>
        /// Parse string anchor into a DateTime object. Return new DateTime in case of errors.
        /// </summary>
        /// <param name="anchor">>Anchor as string</param>
        /// <returns></returns>
        internal DateTime ParseAnchor(String anchor = "")
        {
            var anchorDT = new DateTime();
            try
            {
                if (anchor == "")
                    anchorDT = DateTime.Today;
                else
                    anchorDT = DateTime.Parse(anchor);
            }
            catch (FormatException)
            {
                try
                {
                    anchorDT = DateTime.ParseExact(anchor, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None);
                }
                catch (Exception)
                {
                    return new DateTime();
                }
            }
            catch (Exception)
            {
                return new DateTime();
            }
            return anchorDT;
        }

        /// <summary>
        /// Adjust Anchor related fields to current batch anchor, based on BatchCutOff. Previous day before cutoff, today after cutoff.
        /// </summary>
        internal void AdjustAnchor()
        {
            var NewAnchor = DateTime.Now.Date.Adjust(new Holiday("HE"), DayRuleType.Preceeding); //DateTime.Now.Date;
            var CutOffDay = DateTime.Now.Date.Adjust(new Holiday("HE"), DayRuleType.Following);
            var CutoffAnchor = new DateTime(CutOffDay.Year, CutOffDay.Month, CutOffDay.Day, BatchCutOff.Hours, BatchCutOff.Minutes, BatchCutOff.Seconds);
            //Adjust Anchor
            if (DateTime.Now < CutoffAnchor)
                NewAnchor = DateTime.Now.Date.AddTenor(new Tenor("-1B"));
            if (NewAnchor.Date != DefaultAnchor.Date)
            {
                DefaultAnchor = NewAnchor.Date;
                DefaultAnchorStr = DefaultAnchor.ToString("yyyyMMdd");
                IcingaDefaultHost = "QRA_Batch_" + DefaultAnchor.ToString("yyyyMMdd");
                IcingaPreviousDefaultHost = "QRA_Batch_" + DefaultAnchor.AddTenor(new Tenor("-1B")).ToString("yyyyMMdd");
                Log.LogInformation($"DefaultAnchor changed to {DefaultAnchorStr}.");
            }
        }

        /// <summary>
        /// Setup a proxy http client with default credentials.
        /// </summary>
        /// <param name="proxyUrl"></param>
        internal void SetupProxyHttpHandler(String proxyUrl)
        {
            HttpProxyHandler = new HttpClientHandler
            {
                Proxy = new WebProxy
                {
                    Address = new Uri(proxyUrl),
                    BypassProxyOnLocal = false,
                    UseDefaultCredentials = true
                },
                UseProxy = true
            };
            HttpWithProxy = new HttpClient(HttpProxyHandler);
        }

        /// <summary>
        /// Setup a http client with default credentials.
        /// </summary>
        internal void SetupHttpHandler()
        {
            var clientHandler = new HttpClientHandler
            {
                UseDefaultCredentials = true,
                Credentials = System.Net.CredentialCache.DefaultCredentials
            };
            Http = new HttpClient(clientHandler);
        }

        /// <summary>
        /// Created AuthenticationHeaderValue object from provided encrypted credentials string.
        /// </summary>
        /// <param name="jiraURL">API url.</param>
        /// <param name="jiraURLCredentials">base 64 encoded credenitals.</param>
        internal void AddJiraCredentials(String jiraURL, String jiraURLCredentials)
        {
            JiraURLBase = jiraURL;
            var cred = System.Net.CredentialCache.DefaultNetworkCredentials;
            JiraAuthorization = new AuthenticationHeaderValue("Basic", jiraURLCredentials);
        }

        /// <summary>
        /// Put in place the communication details for VictorOps API.
        /// </summary>
        /// <param name="vopsURL">Base url for API calls.</param>
        /// <param name="ApiId">ID for API usage.</param>
        /// <param name="ApiKey">Key for API usage.</param>
        /// <param name="vopsTeams"></param>
        internal void SetupVictorOps(String vopsURL, String ApiId, String ApiKey, IConfiguration vopsTeams)
        {
            VictorOpsURLBase = vopsURL;
            VictorOpsHeader = new Dictionary<String, String>() { { "Accept", "application/json" }, { "X-VO-Api-Id", ApiId }, { "X-VO-Api-Key", ApiKey } };
            VictorOpsQRATeams = vopsTeams.GetChildren().ToDictionary(x => x.Key, x => x.Value);
            //Fetch Victorops Teams and policies
            LoadVopsGroups();
        }

        /// <summary>
        /// Start observing Sonic (RtRecord) feeds, and set CallbackSonicDataTick as parser of the incoming data.
        /// </summary>
        internal void InitializeRtTickFeeds()
        {
            //reset
            RtDataDict = new Dictionary<string, IDictionary<string, string>>();
            if (!(RtDataSubscription is null))
                RtDataSubscription.Dispose();
            //set
            RtObserveFeedsTick = RtDataSource.GetRtRecordSource(RtDataIDToObserve.ToUpper());
            RtDataSubscription = RtObserveFeedsTick.Subscribe(Observer.Create<IRtTickOut<IRtRecord>>(CallbackSonicDataTick));

        }

        /// <summary>
        /// Populate SonicDataDict with the incoming Sonic (RtData) feeds.
        /// </summary>
        /// <param name="tick"></param>
        internal void CallbackSonicDataTick(IRtTickOut<IRtRecord> tick)
        {
            if (tick.Data.Value != null)
                RtDataDict[tick.TopicId] = tick.Data.Value.Data.ToDictionary(i => i.Key, i => i.Value);
            else
                RtDataDict[tick.TopicId] = new Dictionary<string, string> { { "ERROR", tick.Data.Exception.Message } };
        }

        /// <summary>
        /// Load container into Icinga polling filter dictionary.
        /// </summary>
        /// <param name="contId"></param>
        /// <param name="contUsage"></param>
        internal bool LoadIcingaPolling(string contId, string contUsage)
        {
            try
            {
                IcingaPollingSubscriptionFilters = new Dictionary<string, Dictionary<string, string>>();
                var data = Database.DefaultDatabase.LoadAs<IContainer>(new DBDataLocation(contId, contUsage)).AsMatrix;
                foreach (List<string> l in data)
                {
                    if (l.Count < 3)
                        l.AddRange(Enumerable.Repeat("", 3 - l.Count));
                    if (!IcingaPollingSubscriptionFilters.ContainsKey(l[0]))
                        IcingaPollingSubscriptionFilters[l[0]] = l[1] != "" ? new Dictionary<string, string>() { { l[1], l[2] } } : new Dictionary<string, string>();
                    else if (l[1] != "")
                        IcingaPollingSubscriptionFilters[l[0]][l[1]] = l[2];
                }
                return true;
            }
            catch (Exception ex)
            {
                Log.LogError($"Failed loading container {contId} with usage {contUsage}.");
                Log.LogError(ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Save the current Icinga polling filter dictionary into SF DB.
        /// </summary>
        /// <param name="contName"></param>
        /// <param name="contUsage"></param>
        /// <returns></returns>
        internal bool SaveIcingaPolling(string contName, string contUsage)
        {
            List<List<string>> data = new List<List<string>>();
            foreach (KeyValuePair<string, Dictionary<string, string>> kv in IcingaPollingSubscriptionFilters)
            {
                if (kv.Value.Count > 0)
                    foreach (var kv2 in kv.Value)
                        data.Add(new List<string>() { kv.Key, kv2.Key, kv2.Value });
                else
                    data.Add(new List<string>() { kv.Key });
            }
            var container = new Container(data);
            try
            {
                Database.DefaultDatabase.Save(container, new DBDataLocation(contName, contUsage));
                return true;
            }
            catch (Exception ex)
            {
                Log.LogError(ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// HTTP restAPI wrapper. Returns JsonDocument. Will contain only "error" field, if it failed.
        /// </summary>
        /// <param name="url">Request URL</param>
        /// <param name="useProxy"></param>
        /// <param name="authorization">AuthenticationHeaderValue object with access authorisations.</param>
        /// <param name="extraHeaders">Dictionary of additional HTTP headers. Defaults to { "Accept", "application/json" }.</param> 
        /// <param name="method">HTTP method, default is GET.</param> 
        /// <returns></returns>
        internal async Task<JsonDocument> GetHttpAsync(string url, bool useProxy = false, AuthenticationHeaderValue authorization = null, Dictionary<String, String> extraHeaders = null, HttpMethod method = null)
        {
            JsonDocument outty;
            var httpRequest = new HttpRequestMessage(method is null ? HttpMethod.Get : method, url.Replace(" ", "%20"));
            if (!(authorization is null))
                httpRequest.Headers.Authorization = authorization;
            if (extraHeaders is null) extraHeaders = new Dictionary<String, String>() { { "Accept", "application/json" } };
            foreach (var kv in extraHeaders)
                httpRequest.Headers.Add(kv.Key, kv.Value);
            LogHttpRequest(httpRequest);
            HttpResponseMessage response = useProxy ? await HttpWithProxy.SendAsync(httpRequest) : await Http.SendAsync(httpRequest);
            if (response.IsSuccessStatusCode)
                outty = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            else
                outty = JsonDocument.Parse("{\"error\":" + JsonConvert.ToString(response.ToString()) + "}");
            return outty;
        }

        /// <summary>
        /// Post "data" to "url.
        /// </summary>
        /// <param name="url"></param>
        /// <param name="data"></param>
        /// <param name="useProxy"></param>
        /// <param name="authorization"></param>
        /// <param name="extraHeaders"></param>
        /// <param name="method"></param>
        /// <returns></returns>
        internal async Task<JsonDocument> PostHttpAsync(string url, Dictionary<string, object> data, bool useProxy = false, AuthenticationHeaderValue authorization = null, Dictionary<String, String> extraHeaders = null, HttpMethod method = null)
        {
            JsonDocument outty;
            var httpRequest = new HttpRequestMessage(method is null ? HttpMethod.Post : method, url.Replace(" ", "%20"));
            if (!(authorization is null))
                httpRequest.Headers.Authorization = authorization;
            if (extraHeaders is null) extraHeaders = new Dictionary<String, String>() { { "Accept", "application/json" } };
            foreach (var kv in extraHeaders)
                httpRequest.Headers.Add(kv.Key, kv.Value);
            httpRequest.Content = new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json");
            LogHttpRequest(httpRequest);
            HttpResponseMessage response = useProxy ? await HttpWithProxy.SendAsync(httpRequest) : await Http.SendAsync(httpRequest);
            if (response.IsSuccessStatusCode)
                outty = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            else
                outty = JsonDocument.Parse("{\"error\":" + JsonConvert.ToString(response.ToString()) + "}");
            return outty;
        }

        /// <summary>
        /// Log the full http request statement, for debugging.
        /// </summary>
        /// <param name="context"></param>
        internal void LogHttpRequest(HttpRequestMessage context)
        {
            try
            {
                var requestLog = $"REQUEST HttpMethod: {context.Method}, Path: {context.RequestUri}";
                using (var ms = new MemoryStream())
                {
                    if (!(context.Content is null))
                    {
                        context.Content.CopyToAsync(ms).ConfigureAwait(false);
                        var bodyAsText = Encoding.ASCII.GetString(ms.ToArray());
                        if (string.IsNullOrWhiteSpace(bodyAsText) == false)
                        {
                            requestLog += $", Body : {bodyAsText}";
                        }
                    }
                }
                Log.LogDebug(requestLog);
            }
            finally
            { }
        }

        /// <summary>
        /// Populate VictorOpsPolicies with all policies in the bank. As a Dictnionary of Team:ListOfPolicies
        /// </summary>
        internal void LoadVopsGroups()
        {
            String requestUrl = VictorOpsURLBase + "policies";
            var postData = GetHttpAsync(requestUrl, true, null, VictorOpsHeader).Result;
            var data = JsonConvert.DeserializeObject<Dictionary<string, object>>(postData.RootElement.ToString());
            //{"policies": [ { "policy": { "name": "MIT-MSSQL", "slug": "pol-5adLaTAEdzQtWHwl", "_selfUrl": "/api-public/v1/policies/pol-5adLaTAEdzQtWHwl" }, "team": { "name": "MIT-MSSQL", "slug": "team-QZcxMjrNCLmyfPT5" }},... ] }
            if (!data.ContainsKey("policies"))
            {
                string error = data.ContainsKey("error") ? data["error"].ToString() : "Unknown issue.";
                Log.LogError($"Failed fetching VictorOps policies. Error:\n{error}");
                return;
            }
            var policiesList = JsonConvert.DeserializeObject<List<Dictionary<string, Dictionary<string, string>>>>(JsonConvert.SerializeObject(data["policies"]));
            VictorOpsPolicies["headers"] = new Dictionary<string, List<string>> { ["policy name"] = new List<string>() { "policy slug", "policy url" } };
            foreach (var polTeam in policiesList)
            {
                var team = polTeam["team"];
                var pol = polTeam["policy"];
                if (!VictorOpsPolicies.ContainsKey(team["name"]))
                    VictorOpsPolicies[team["name"]] = new Dictionary<string, List<string>>();
                VictorOpsPolicies[team["name"]][pol["name"]] = new List<string>() { pol["slug"], pol["_selfUrl"] };
                VictorOpsAllTeams[team["name"]] = team["slug"];
            }
        }

        #endregion

        #region Robot helpers
        /// <summary>
        /// Convert string into HH:MM formated time string.
        /// </summary>
        /// <param name="timeIn"></param>
        /// <param name="timeOut">output var</param>
        /// <returns></returns>
        private bool ParseTimeIntoHHMM(string timeIn, out string timeOut)
        {
            if (timeIn.Contains(":"))
            {
                timeOut = timeIn.Length == 5 ? timeIn : ("0" + timeIn);
                return true;
            }
            if (timeIn.Length == 3)
                timeIn = "0" + timeIn;
            if (timeIn.Length == 4)
            {
                timeOut = timeIn.Substring(0, 2) + ":" + timeIn.Substring(2, 2);
                return true;
            }
            timeOut = "";
            return false;
        }

        /// <summary>
        /// Grab status-relevant details from Icinga service and return as  a list of messages.
        /// </summary>
        /// <param name="IcingaService"></param>
        /// <param name="Compact">Limit size of the output message.</param>
        /// <param name="IncludeServer">Include server details in the message.</param>
        /// <param name="OneLine">Limit message to one line.</param>
        /// <returns></returns>
        private List<String> IcignaServiceToStatus(Service IcingaService, bool Compact = false, bool IncludeServer = true, bool OneLine = false)
        {
            List<String> messageOut = new List<String>();
            int CompactLengthLimit = 100;
            int OneLineLimit = 20;
            var data = ParseIcingaAttributes(IcingaService.Attributes);
            var lastCheckResult = IcingaService.RuntimeAttributes.LastCheckResult;
            var perfData = lastCheckResult.ContainsKey("performance_data") ? lastCheckResult["performance_data"] : null;
            var pluginOutput = lastCheckResult.ContainsKey("output") ? lastCheckResult["output"].ToString() : "";
            var state = lastCheckResult.ContainsKey("state") ? Int32.Parse(lastCheckResult["state"].ToString().Replace(".0", "")) : 99;
            string status = IcingaStatesMap.ContainsKey(state) ? IcingaStatesMap[state] : "UNKNOWN";
            if (OneLine)
            {
                var shortErr = "";
                if (!pluginOutput.StartsWith("{") && !pluginOutput.EndsWith("{"))//if not a json message, than include.
                    shortErr = pluginOutput;
                else if (data["ERRORS"].ToString() != "")
                    shortErr = data["ERRORS"].ToString();
                shortErr = shortErr.Length>OneLineLimit ?  shortErr.Substring(0, 20) + "..." : shortErr;
                messageOut.Add("<b>" + IcingaService.ServiceName + (IncludeServer ? (" on " + data["SERVER"].ToString()) : "") + ", status:</b> <i>" + (shortErr!="" ? shortErr : status) + "</i>");
                return messageOut;
            }
            else
                messageOut.Add("<b>" + IcingaService.GetIcingaName() + (IncludeServer ? (" on " + data["SERVER"].ToString()) : "") + ", status:</b>    <i>" + status + ":</i>");
            if (!pluginOutput.StartsWith("{") && !pluginOutput.EndsWith("{"))//if not a json message, than include.
            {
                var pluginMsg = pluginOutput;
                if (Compact && pluginMsg.Length > CompactLengthLimit) pluginMsg = pluginMsg.Substring(0, CompactLengthLimit) + "...";
                messageOut.Add(pluginMsg);
            }
            if (data["WARNINGS"].ToString() != "" && !Compact)
            {
                messageOut.Add("<i>WARNINGS:</i>");
                var warMsg = data["WARNINGS"].ToString();
                if (Compact && warMsg.Length > CompactLengthLimit) warMsg = warMsg.Substring(0, CompactLengthLimit) + "...(truncated)";
                messageOut.Add(HttpUtility.HtmlEncode(warMsg));
            }
            if (data["ERRORS"].ToString() != "")
            {
                if (!Compact) messageOut.Add("<i>ERRORS:</i>");
                var errMsg = data["ERRORS"].ToString();
                if (Compact && errMsg.Length > CompactLengthLimit) errMsg = errMsg.Substring(0, CompactLengthLimit) + "...(truncated)";
                messageOut.Add(HttpUtility.HtmlEncode(errMsg));
            }
            return messageOut;
        }

        /// <summary>
        /// Parse input string into a dictionary with icinga host, environemt, and the rest of input in numbered entries.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private SortedDictionary<String, String> ParseRobotInput(String input)
        {
            AdjustAnchor();
            SortedDictionary<String, String> outDict = new SortedDictionary<String, String>() { { "host", IcingaDefaultHost }, { "e", IcingaDefaultEnv } };
            HashSet<String> keys = new HashSet<string>();
            if (input != null)
            {
                var varsTmp = input.Split("#").ToList();
                int i = 0;
                foreach (var t in varsTmp)
                {
                    var kv = t.Split("=");
                    string k = kv[0].Trim();
                    string v = kv.Length > 1 ? kv[1].Trim() : "";
                    string key = "";
                    if (v != "")
                    {
                        key = k.ToUpper() == "H" ? "host" : (k.ToUpper() == "A" ? "anchorStr" : k.ToLower());
                        if (k.ToUpper() == "H") outDict["host"] = v;
                        else if (k.ToUpper() == "A") outDict["anchorStr"] = v;
                        else outDict[k.ToLower()] = v;
                    }
                    else if (k != "")
                    {
                        key = i++.ToString();
                        outDict[key] = k;
                    }
                    keys.Add(key);
                }
            }
            if (!outDict.ContainsKey("anchorStr")) outDict["anchorStr"] = outDict.ContainsKey("host") ? outDict["host"].Substring(outDict["host"].Length - 8) : DefaultAnchorStr;
            else outDict["host"] = keys.Contains("host") ? outDict["host"] : ("QRA_Batch_" + outDict["anchorStr"]);
            return outDict;
        }

        /// <summary>
        /// Convert all Service attributes into a dictionary for easier access.
        /// </summary>
        /// <param name="attributes"></param>
        /// <returns></returns>
        private SortedDictionary<String, object> ParseIcingaAttributes(ServiceAttributes attributes)
        {
            SortedDictionary<String, object> outDict = new SortedDictionary<String, object>(attributes.GetType().GetProperties().ToDictionary(t => t.Name.ToUpper(), t => t.GetValue(attributes))); //get attributes

            //custom vars
            foreach (KeyValuePair<String, object> kv in attributes.Vars)
            {
                if (kv.Value != null && kv.Value.ToString().Contains("_:_"))
                {
                    var allFields = kv.Value.ToString().Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                    foreach (String f in allFields)
                    {
                        var tmp = f.Split("_:_");
                        outDict[tmp[0].ToUpper()] = tmp[1];
                    }
                }
                else
                    outDict[kv.Key.ToUpper()] = kv.Value != null ? kv.Value : "";
            }
            return outDict;
        }

        /// <summary>
        /// Convert a list of lists of strings into a HTML formatted table.
        /// </summary>
        /// <param name="inputs"></param>
        /// <param name="containsHeaders">If true, then first element in inputs is treated as a header.</param>
        /// <returns></returns>
        private String ListIntoHTMLTable(List<List<String>> inputs, bool containsHeaders = true)
        {
            List<String> outList = new List<String>();
            //Add headers, if relevant
            outList.Add("<table>" + (containsHeaders ? "<thead>" : "<tbody>") + "<tr><td>" + String.Join("</td><td>", inputs[0]) + "</td></tr>" + (containsHeaders ? "</thead><tbody>" : ""));

            //Consume the rest
            foreach (var line in inputs.Skip(1))
                outList.Add("<tr><td>" + String.Join("</td><td>", line as List<string>) + "</td></tr>");
            outList.Add("</tbody></table>");
            return String.Join("", outList);
        }

        /// <summary>
        /// Convert a list of strings into a HTML formatted table.
        /// </summary>
        /// <param name="inputs"></param>
        /// <param name="containsHeaders">If true, then first element in inputs is treated as a header.</param>
        /// <returns></returns>
        private String ListIntoHTMLTable(List<String> inputs, bool containsHeaders = true)
        {
            List<String> outList = new List<String>();
            //Add headers, if relevant
            outList.Add("<table>" + (containsHeaders ? "<thead>" : "<tbody>") + "<tr><td>" + inputs[0] + "</td></tr>" + (containsHeaders ? "</thead><tbody>" : ""));

            //Consume the rest
            foreach (var line in inputs.Skip(1))
                outList.Add("<tr><td>" + line.ToString() + "</td></tr>");
            outList.Add("</tbody></table>");
            return String.Join("", outList);
        }

        /// <summary>
        /// Use Windows Managment Instrumentation to execude cmd on server.
        /// </summary>
        /// <param name="user">User name to be incldued in the log.</param>
        /// <param name="server">Server name.</param>
        /// <param name="cmd">Full cmd to be executed.</param>
        /// <param name="logfile"></param>
        /// <param name="streamid"></param>
        /// <param name="msgId"></param>
        /// <param name="executable"></param>
        /// <returns></returns>
        private async Task RunOnRemote(string user, string server, string cmd, string logfile, string streamid, string msgId = "", string executable = "C:\\App\\python27\\python.exe")
        {
            var psCommand = executable + " " + cmd;
            var messageOut = new List<String>();
            var t0 = DateTime.Now;
            Log.LogInformation("RunOnRemote will execute on " + (server!="" ? server : Dns.GetHostName()) + ", requested by " + user + ", with CMD: " + psCommand);
            var PSret = await PS.RunCmd(psCommand, server);
            if (PSret.Item1)
            {
                Log.LogInformation("RunOnRemote finished in " + (DateTime.Now - t0).TotalSeconds.ToString() + "sec. Returned:\n" + string.Join("\n", PSret));
                messageOut.Add(msgId + (msgId != "" ? " " : "") + "Task finished. See outputfile: " + logfile);
            }
            else
            {
                Log.LogError("RunOnRemote failed: " + PSret.Item2[0]);
                string errMsg = PSret.Item2[0];
                if (PSret.Item2[0].Contains("Use gpedit.msc"))//Due to  "The WinRM client cannot process the request." since Group Policies are blocking it.
                    errMsg = errMsg.Substring(0, errMsg.IndexOf("Use gpedit.msc") - 1);
                messageOut.Add(msgId + (msgId != "" ? " " : "") + "Failed executing the CMD remotely. Error: " + errMsg);
            }
            _ = SendAsHtmlStream(streamid, messageOut);
        }

        /// <summary>
        /// Parse Jira's Dictionary of (String, object) response into Dictionary of (ticket's key, Dictionary of (keys, ticket fields)).
        /// </summary>
        /// <param name="inputs"></param>
        /// <returns></returns>
        private Dictionary<String, Dictionary<string, object>> ParseJiraResponseToTickets(JsonDocument inputs)
        {
            Dictionary<String, Dictionary<string, object>> outputs = new Dictionary<String, Dictionary<string, object>>();
            JsonElement issues;
            if (inputs.RootElement.TryGetProperty("issues", out issues))
            {
                var inputsDeserialized = JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(issues.ToString());
                foreach (var o in inputsDeserialized)
                    outputs[o["key"].ToString()] = JsonConvert.DeserializeObject<Dictionary<string, object>>(JsonConvert.SerializeObject(o));
            }
            return outputs;
        }

        /// <summary>
        /// Given victorOps team name, return the current onCall details.
        /// </summary>
        /// <param name="team">victorOps team name.</param>
        /// <returns></returns>
        private Dictionary<String, object> GetVopsSchedule(String team)
        {
            String requestUrl = VictorOpsURLBase + $"team/{team}/oncall/schedule";
            var getData = GetHttpAsync(requestUrl, true, null, VictorOpsHeader).Result;
            JsonElement schedule;
            Dictionary<String, object> output = new Dictionary<String, object>();
            if (getData.RootElement.TryGetProperty("schedule", out schedule))
            {
                var scheduleDeserialized = JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(schedule.ToString());
                foreach (var sched in scheduleDeserialized)
                {
                    if (sched.ContainsKey("onCall"))
                        output = sched;
                }
            }
            else if (getData.RootElement.TryGetProperty("error", out schedule))
            {
                Log.LogError(schedule.ToString());
                output = new Dictionary<String, object>() { { "error", schedule.ToString() } };
            }
            return output;
        }

        /// <summary>
        /// Get user details from victorOps, given victorOps user name.
        /// </summary>
        /// <param name="user">victrOps username.</param>
        /// <returns></returns>
        private Dictionary<String, String> GetVopsUser(String user)
        {
            String requestUrl = VictorOpsURLBase + $"user/{user}";
            var getData = GetHttpAsync(requestUrl, true, null, VictorOpsHeader).Result;
            var tmp = JsonConvert.DeserializeObject<Dictionary<string, object>>(getData.RootElement.ToString());
            Dictionary<String, String> output = new Dictionary<string, string>();
            output["name"] = tmp["firstName"].ToString() + " " + tmp["lastName"].ToString();
            output["username"] = tmp["username"].ToString();
            output["email"] = tmp["email"].ToString();
            output["phone"] = "missing";
            try
            {
                requestUrl = VictorOpsURLBase + $"user/{user}/contact-methods/phones";
                getData = GetHttpAsync(requestUrl, true, null, VictorOpsHeader).Result;
                tmp = JsonConvert.DeserializeObject<Dictionary<string, object>>(getData.RootElement.ToString());
                if (tmp.ContainsKey("contactMethods"))
                {
                    var contact = JsonConvert.DeserializeObject<List<Dictionary<string, string>>>(tmp["contactMethods"].ToString());
                    var firstContact = (from e in contact
                                        orderby e["rank"] ascending
                                        select e).First();
                    output["phone"] = firstContact["value"];
                }
            }
            catch
            {
                output["phone"] = "error";
            }
            return output;
        }

        /// <summary>
        /// VOPS API call to create new incident.
        /// </summary>
        /// <param name="sender">VOPS user</param>
        /// <param name="recipient">VOPS user</param>
        /// <param name="subject"></param>
        /// <param name="text"></param>
        /// <returns></returns>
        private Dictionary<String, object> SentVopsAlert(String sender, String recipient, String subject, String text)
        {
            bool isUser = !recipient.Contains("_") && !recipient.Contains("-") && !recipient.Contains(" ");
            if (!isUser)
            {
                var team = VictorOpsAllTeams.Where(kv => kv.Key.ToUpper() == recipient.ToUpper()).Select(kv => kv.Value).ToList();
                if (team.Count == 0)
                    return new Dictionary<string, object>() { { "error", recipient + " does not seem to be a user name, and does not match any VictorOps team." } };
                recipient = team[0];
            }
            Dictionary<String, object> body = new Dictionary<string, object>() {
                { "userName",           sender },
                { "summary",            subject },
                { "details",            text },
                { "targets",            new List<Dictionary<string, object>>() { new Dictionary<string, object> (){ {"type", isUser?"User":"Team"}, {"slug",recipient} } } },
                { "isMultiResponder",   true }
            };
            String requestUrl = VictorOpsURLBase + "incidents";
            var postData = PostHttpAsync(requestUrl, body, true, null, VictorOpsHeader).Result;
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(postData.RootElement.ToString());
        }

        /// <summary>
        /// Hand over on-call for "rotation" from "sender" to "recipient".
        /// </summary>
        /// <param name="sender">VOPS user</param>
        /// <param name="recipient">VOPS user</param>
        /// <param name="team">VOPS team slug</param>
        /// <returns></returns>
        private Dictionary<String, object> HandOverVops(String sender, String recipient, String team)
        {
            var teamSlug = VictorOpsAllTeams.Where(kv => kv.Key.ToUpper() == team.ToUpper()).Select(kv => kv.Value).FirstOrDefault();
            if (teamSlug == String.Empty)
                teamSlug = VictorOpsQRATeams.Where(kv => kv.Key.ToUpper() == team.ToUpper()).Select(kv => kv.Value).FirstOrDefault();
            if (teamSlug == String.Empty)
                return new Dictionary<string, object>() { { "error", team + " does not match any VictorOps team." } };
            var rotation = "";
            var onCall = GetVopsSchedule(teamSlug);
            if (onCall.ContainsKey("rotationName"))
                rotation = onCall["rotationName"].ToString();
            else
                return new Dictionary<string, object>() { { "error", "No current on-call rotation found for " + team } };
            if (VictorOpsPolicies.ContainsKey(team))
            {
                if (VictorOpsPolicies[team].Count == 1)
                    rotation = VictorOpsPolicies[team][rotation][0];
                else
                {
                    var tmp = VictorOpsPolicies[team].Where(kv => kv.Key.ToLower().Contains(rotation.ToLower()) || rotation.ToLower().Contains(kv.Key.ToLower())).ToDictionary(kv => rotation, kv => kv.Value);
                    rotation = tmp[rotation][0];
                }
            }
            else
                return new Dictionary<string, object>() { { "error", $"Cannot find policy matching team \"{team}\" and rotation \"{rotation}\"." } };
            Dictionary<String, object> body = new Dictionary<string, object>() {
                { "fromUser", sender },
                { "toUser",   recipient},
            };
            String requestUrl = VictorOpsURLBase + $"policies/{rotation}/oncall/user";
            var postData = PostHttpAsync(requestUrl, body, true, null, VictorOpsHeader, HttpMethod.Patch).Result;
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(postData.RootElement.ToString());
        }

        /// <summary>
        /// Get file contest using full path.
        /// </summary>
        /// <param name="path">Full file path name.</param>
        /// <returns></returns>
        static public IEnumerable<string> GetFile(string path)
        {
            List<string> outArr = new List<string>();
            if (path.Contains("%"))
                path = Environment.GetEnvironmentVariable(path.Replace("%", ""));
            //FileInfo file = new FileInfo(path);
            if (File.Exists(path))
            {//Read even if locked
                FileStream logFileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                StreamReader logFileReader = new StreamReader(logFileStream);
                while (!logFileReader.EndOfStream)
                    outArr.Add(logFileReader.ReadLine());

                logFileReader.Close();
                logFileStream.Close();
            }
            else if (Directory.Exists(path))
            {
                outArr = Directory.GetDirectories(path).ToList();
                outArr.AddRange(Directory.GetFiles(path, "*.*").ToList());
            }
            else
                outArr.Add("wrong path:\n" + path);
            return outArr.ToArray();
        }
        #endregion

        #region Robot functions
        /// <summary>
        /// Get ping, name, and IP from current server.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> Ping(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            String host = Dns.GetHostName();
            String ip = Dns.GetHostEntry(host).AddressList[0].ToString();
            DateTime t0 = DateTime.ParseExact(inputs["time0"], inputs["timeformat"], new System.Globalization.CultureInfo("en-US"));
            return new List<string>() { "<mention uid=\"" + inputs["thisuid"] + "\"/>" + " pong. " + Environment.UserName + " running on " + host + " (" + ip + ") " + (DateTime.Now - t0).TotalMilliseconds.ToString() + "ms." };
        }

        /// <summary>
        /// Get current server.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> GetHost(String input, String user)
        {
            return new List<string>() { Dns.GetHostName() };
        }

        /// <summary>
        /// Return Symphony details for B-user provided in the input.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> GetUserInfo(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            List<String> outputs = new List<string>();
            if (!inputs.ContainsKey("0"))
                outputs.Add("Specify user in your input.");
            return GetUser(inputs["0"]);
        }

        /// <summary>
        /// Get Symphony user based on user Symphony ID.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> GetCurrentUserInfo(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            return GetUser(long.Parse(inputs["thisuid"]));
        }

        /// <summary>
        /// get status of "*service*" from "*host*", on icinga "*environment*".
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> IcingaStatus(String input, String user)
        {
            List<String> messageOut = new List<String>();
            var inputs = ParseRobotInput(input);
            inputs["e"] = inputs["e"].ToUpper();
            if (IcingaSupportedEnvs.Contains(inputs["e"]) && IcingaClients.ContainsKey(inputs["e"]))
            {
                var IcingaService = TryGetService(inputs["e"],inputs["host"], inputs["0"]);
                if (IcingaService is null)
                   return new List<String>() { "Looks like " + inputs["0"] + " doesn't exist on " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
                messageOut = IcignaServiceToStatus(IcingaService);
            }
            else
                messageOut.Add("Currently only supporting IcingaEnv(s)=" + String.Join(",", IcingaSupportedEnvs));
            return messageOut;
        }

        /// <summary>
        /// get "field" from "service" from "host", on icinga "environment".
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> IcingaServiceDetails(String input, String user)
        {
            String messageOut = "";
            var inputs = ParseRobotInput(input);
            inputs["e"] = inputs["e"].ToUpper();
            if (IcingaSupportedEnvs.Contains(inputs["e"]) && IcingaClients.ContainsKey(inputs["e"]))
            {
                var IcingaService = TryGetService(inputs["e"], inputs["host"], inputs["0"]);
                if (IcingaService is null)
                    return new List<String>() { "Looks like " + inputs["0"] + " doesn't exist on " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
                var data = ParseIcingaAttributes(IcingaService.Attributes);
                String Field = inputs["1"];
                String val = data.ContainsKey(Field.ToUpper()) ? data[Field.ToUpper()].ToString() : (Field + " not available on this service.");
                var perfData = IcingaService.RuntimeAttributes.LastCheckResult.ContainsKey("performance_data") ? IcingaService.RuntimeAttributes.LastCheckResult["performance_data"] : null;
                messageOut = IcingaService.GetIcingaName() + " " + Field + ": " + HttpUtility.HtmlEncode(val);
            }
            else
                messageOut = "Currently only supporting IcingaEnv(s)=" + IcingaSupportedEnvs.ToString();
            return new List<string>() { messageOut };
        }

        /// <summary>
        /// Return a table of counter of states of services on the batch host. If status filter provided, then a list of services mathcing that status.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> IcingaBatchStatus(String input, String user)
        {
            String messageOut;
            var inputs = ParseRobotInput(input);
            inputs["e"] = inputs["e"].ToUpper();
            var IcingaServices = IcingaClients[inputs["e"]].TryGetHostServices(inputs["host"]).Result;
            if (IcingaServices is null)
                return new List<String>() { "Could not fetch services for host " + inputs["host"] + " in Icinga " + inputs["e"] + "." };

            if (inputs.ContainsKey("s"))//filter only specific states
            {
                var filterStatus = default(Int32);
                if (!Int32.TryParse(inputs["s"].Replace(".0", ""), out filterStatus))//if not an integer, then convert string into integer
                {
                    filterStatus = IcingaStatesMap.Where(kv => kv.Value == inputs["s"].ToUpper()).Select(kv => kv.Key).FirstOrDefault();
                }
                if (filterStatus == default(Double))
                    return new List<string>() { "The provided state, \"" + inputs["s"] + "\", doesn't match any of the states in Icinga:", String.Join(";", IcingaStatesMap.Select(kv => kv.Key + "=" + kv.Value)) };
                inputs["s"] = filterStatus.ToString();
                IcingaServices = IcingaServices.Where(s => (s.RuntimeAttributes.LastCheckResult is null ? 99 : Int32.Parse(s.RuntimeAttributes.LastCheckResult["state"].ToString().Replace(".0", ""))) == filterStatus).ToList();
            }
            //Filter, default is isBatch=True
            List<String> Filters = new List<string>() { "isBatch$True" };
            if (inputs.ContainsKey("f"))
                Filters.AddRange(inputs["f"].Split("&").ToList());
            if (inputs.ContainsKey("fo"))
                Filters = inputs["fo"].Split("&").ToList();
            foreach (var f in Filters)
            {
                var tmp = f.ToUpper().Split("$");
                if (tmp.Length != 2) continue;
                List<Service> RemainingIcingaServices = new List<Service>();
                foreach (var s in IcingaServices)
                {
                    var data = ParseIcingaAttributes(s.Attributes);
                    if (tmp[0] == "SERVICEGROUP")
                    {
                        var groups = (data["GROUPS"] as List<string>).Select(v => v.ToUpper()).ToList();
                        if (groups.Contains(tmp[1])) RemainingIcingaServices.Add(s);
                    }
                    else
                    {
                        if (!data.ContainsKey(tmp[0])) continue;
                        if (data[tmp[0]].ToString().ToUpper() == tmp[1]) RemainingIcingaServices.Add(s);
                    }
                }
                IcingaServices = RemainingIcingaServices;
            }

            if (inputs.ContainsKey("s"))//list services by name
            {
                var status = IcingaStatesMap.ContainsKey(Int32.Parse(inputs["s"])) ? IcingaStatesMap[Int32.Parse(inputs["s"])] : "UNKNOWN";
                var names = IcingaServices.Select(s => s.GetIcingaName().Replace(inputs["host"] + "!", "")).ToList();
                var states = new List<String>() { "<b>List of services on " + inputs["host"] + " with status " + status + "</b>" };
                states.AddRange(names);
                messageOut = ListIntoHTMLTable(states);
            }
            else//count services per state
            {
                var states = new List<List<String>>() { new List<String>() { "<b>State</b>", "<b>Count of services on " + inputs["host"] + "</b>" } };
                foreach (var line in IcingaServices.GroupBy(s => s.RuntimeAttributes.LastCheckResult is null ? "99" : s.RuntimeAttributes.LastCheckResult["state"].ToString().Replace(".0", ""))
                        .Select(group => new { Metric = group.Key, Count = group.Count() })
                        .OrderBy(x => x.Metric))
                {
                    var status = IcingaStatesMap.ContainsKey(Int32.Parse(line.Metric)) ? IcingaStatesMap[Int32.Parse(line.Metric)] : "UNKNOWN";
                    states.Add(new List<String>() { status, line.Count.ToString() });
                }
                messageOut = ListIntoHTMLTable(states);
            }
            return new List<string>() { messageOut };
        }

        /// <summary>
        /// Check if all batch jobs (PM or AM or both) have finished by now. Return status of the unfinished ones.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> IcingaBatchReady(String input, String user)
        {
            List<String> messageOut = new List<String>();
            var inputs = ParseRobotInput(input);
            inputs["e"] = inputs["e"].ToUpper();
            if (IcingaSupportedEnvs.Contains(inputs["e"]) && IcingaClients.ContainsKey(inputs["e"]))
            {
                if (inputs.ContainsKey("a"))
                    inputs["host"] = "QRA_Batch_" + inputs["a"];
                var IcingaServices = IcingaClients[inputs["e"]].TryGetHostServices(inputs["host"]).Result;
                var isBatch = "TRUE";
                var isPMFilter = "";
                if (inputs.ContainsKey("0") && new List<string>() { "AM", "PM" }.Contains(inputs["0"].ToUpper()))
                    isPMFilter = inputs["0"].ToUpper() == "PM" ? "0" : "1";
                List<Service> RemainingIcingaServices = new List<Service>();
                foreach (var s in IcingaServices)
                {
                    var data = ParseIcingaAttributes(s.Attributes);
                    if (data.ContainsKey("ISBATCH") && data.ContainsKey("ISPM"))
                    {
                        var state = Int32.Parse(s.RuntimeAttributes.LastCheckResult is null ? "99" : s.RuntimeAttributes.LastCheckResult["state"].ToString().Replace(".0", ""));
                        if (data["ISBATCH"].ToString().ToUpper() == isBatch && data["ISPM"].ToString().ToUpper() != isPMFilter && state > 1) RemainingIcingaServices.Add(s);
                    }
                }
                if (RemainingIcingaServices.Count > 0)
                {
                    //var perfData = RemainingIcingaServices[0].RuntimeAttributes.LastCheckResult.ContainsKey("performance_data") ? RemainingIcingaServices[0].RuntimeAttributes.LastCheckResult["performance_data"] : null;
                    messageOut.Add("Still waiting for " + RemainingIcingaServices.Count.ToString() + " " + (isPMFilter == "" ? "batch" : (isPMFilter == "0" ? "PM" : "AM")) + " jobs:");
                    if (RemainingIcingaServices.Count > 5)//Too many jobs to count
                    {
                        var states = new List<List<String>>() { new List<String>() { "<b>State</b>", "<b>Count of services on " + inputs["host"] + "</b>" } };
                        foreach (var line in RemainingIcingaServices.GroupBy(s => s.RuntimeAttributes.LastCheckResult is null ? "99" : s.RuntimeAttributes.LastCheckResult["state"].ToString().Replace(".0", ""))
                                .Select(group => new { Metric = group.Key, Count = group.Count() })
                                .OrderBy(x => x.Metric))
                        {
                            var status = IcingaStatesMap.ContainsKey(Int32.Parse(line.Metric)) ? IcingaStatesMap[Int32.Parse(line.Metric)] : "UNKNOWN";
                            states.Add(new List<String>() { status, line.Count.ToString() });
                        }
                        messageOut.Add(ListIntoHTMLTable(states));
                    }
                    else
                        foreach (var s in RemainingIcingaServices)
                            messageOut.AddRange(IcignaServiceToStatus(s, true));
                }
                else
                    messageOut.Add("All " + (isPMFilter == "" ? "batch" : (isPMFilter == "0" ? "PM" : "AM")) + " jobs marked as isBatch=True seem to have finished with no errors.");
            }
            else
                messageOut.Add("Currently only supporting IcingaEnv(s)=" + String.Join(",", IcingaSupportedEnvs));
            return messageOut;
        }

        /// <summary>
        /// Check if PM jobs are ready.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> IcingaPMBatchReady(String input, String user)
        {
            return IcingaBatchReady(input + "#PM", user);
        }

        /// <summary>
        /// ([*s=server*]#*job*#[*r=rows*]#[*c=clone*]) - get last "*rows*" (defaults to 10 last rows) from log (defaults to proclog, if "*clone*" not specified) on "*server*" (defaults to checking previous day QRA_Batch in icinga).
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> ReadFile(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            String filePath = "";
            List<String> logLines = new List<string>();
            if (inputs.ContainsKey("d"))
            {
                filePath = inputs["d"];
                if (!inputs.ContainsKey("r")) inputs["r"] = "20";
            }
            else if (!inputs.ContainsKey("f"))
            {
                if (!inputs.ContainsKey("s"))
                {
                    inputs["e"] = inputs["e"].ToUpper();
                    var IcingaService = TryGetService(inputs["e"], inputs["host"], inputs["0"]);
                    if (IcingaService is null)
                        return new List<String>() { "Looks like " + inputs["0"] + " doesn't exist on " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
                    inputs["0"] = IcingaService.ServiceName;
                    var data = ParseIcingaAttributes(IcingaService.Attributes);
                    inputs["s"] = data.ContainsKey("SERVER") ? data["SERVER"].ToString() : Dns.GetHostName();
                    filePath = data.ContainsKey("PROCLOG") && !inputs.ContainsKey("c") ? data["PROCLOG"].ToString() : "";
                }
                if (!inputs.ContainsKey("r")) inputs["r"] = "10";
                if (filePath == "")
                    filePath = Path.Join("C:\\LingoNightRider", inputs["0"], !inputs.ContainsKey("c") ? "procLog" : "logs", !inputs.ContainsKey("c") ? (inputs["0"] + ".log") : (inputs["anchorStr"] + "\\" + inputs["c"] + ".log"));
                filePath = filePath.Replace("C:\\", "\\\\" + inputs["s"] + "\\");
            }
            else
            {
                filePath = inputs["f"];
                if (!inputs.ContainsKey("r")) inputs["r"] = "20";
            }
            int rowsToRead = Int32.Parse(inputs["r"]);
            logLines = GetFile(filePath).ToList();
            if (rowsToRead > 0 && logLines.Count > rowsToRead)
            {
                logLines.Insert(0, "<i>...(provide r=X to get X entries out)</i>");
                logLines = logLines.AsEnumerable().Reverse().Take(rowsToRead).Reverse().ToList();
            }
            logLines.Insert(0, "<b>" + filePath + "</b><hr/>");
            return logLines;
        }

        /// <summary>
        /// Return path to the local help file.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> GetHelp(String input, String user = null)
        {
            var helpUrl = "https://confluence.danskenet.net/display/SFSTRAT/QRA+Symphony+bot";
            var inputs = ParseRobotInput(input);
            List<string> help = new List<string>() { helpUrl + "<br/>" };
            if (inputs.ContainsKey("0"))
            {
                if (RobotFuncsHelp.ContainsKey(inputs["0"].ToUpper()))
                {
                    var kv = RobotFuncsHelp[inputs["0"].ToUpper()];
                    help.Add("<b>" + inputs["0"].ToLower() + "</b>" + kv.First() + "     -----     " + kv.Last());
                    help.Add("<hr/>Examples: ");
                    help.Add(RobotFuncsExamples[inputs["0"].ToUpper()]);
                }
                else
                    help.Add("Unsupported function " + inputs["0"] + ", no help found for it.");
            }
            else
            {
                var funcs = new List<List<String>>() { new List<String>() { "<b>Function call ([] indicates optional input requiring 'key=value' format)</b>", "<b>Description</b>", "<b>Examples</b>" } };
                foreach (var kve in RobotFuncsHelp.Zip(RobotFuncsExamples, Tuple.Create))
                    funcs.Add(new List<String>() { "<b>" + kve.Item1.Key.ToLower() + "</b>" + kve.Item1.Value.First(), kve.Item1.Value.Last(), kve.Item2.Value });
                help.Add(ListIntoHTMLTable(funcs));
            }
            return help;
        }

        /// <summary>
        /// Will add specific error for specific job group (based on input fitlers) into QRAbatchIgnoreList.json. Will ask for validation, before adding.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user">Ignored</param>
        /// <returns></returns>
        private List<String> AddToBatchSilencingList(String input, String user = null)
        {
            var inputs = ParseRobotInput(input);
            List<String> outputs = new List<string>();
            String validationKey = KeyGenerator.GetUniqueKey(16);
            // TODO Remove when documentaiton updated. For backward compatibility
            if (inputs.ContainsKey("j") && inputs.ContainsKey("e") && (!inputs.ContainsKey("0") || !inputs.ContainsKey("1")))
            {
                inputs["0"] = inputs["j"];
                inputs["1"] = inputs["e"];
            }
            // **********************
            if (inputs.ContainsKey("0") && inputs.ContainsKey("1"))
            {
                if (inputs.ContainsKey("validationkey"))
                {
                    //remove validation key and match with CurrentTasks
                    var thisTuple = new Tuple<string, string>(inputs["validationkey"], JsonConvert.SerializeObject(inputs));
                    if (CurrentTasks.Contains(thisTuple))
                    {
                        CurrentTasks.Remove(thisTuple);
                        string BatchSilenceExe = GetFile(BatchSilenceExePath).Last() + "\\batchSilencedList.exe";
                        var ret = PS.RunCmd(BatchSilenceExe + " --anchor " + inputs["anchorStr"] + " --line " + inputs["0"] + "#" + inputs["1"]).Result;
                        outputs.Add((ret.Item1 ? "" : "Failed adding to silencing. Error: ") + ret.Item2.Last());
                    }
                    else
                        outputs.Add("Your request didn't match any active queries. Please try again without \"validationkey\" variable.");
                }
                else
                {
                    inputs["validationkey"] = validationKey;
                    String properRequest = BotTag + " silence(a=" + inputs["anchorStr"] + "#" + inputs["0"] + "#" + inputs["1"] + "#validationkey=" + validationKey + ")";
                    CurrentTasks.Add(new Tuple<string, string>(validationKey, JsonConvert.SerializeObject(inputs)));
                    outputs.Add("To validate your request, please send this message:");
                    outputs.Add(properRequest);
                }
            }
            else
            {
                String fullFile = BatchSilenceFile.Replace("YYYYMMDD", inputs["anchorStr"]);
                List<String> logLines = GetFile(fullFile).ToList();
                logLines.RemoveAt(0);
                outputs = logLines;
            }
            return outputs;
        }

        /// <summary>
        /// OK the specified job, but check if provided user is allowed.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> OkTheJob(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            inputs["e"] = inputs["e"].ToUpper();
            //Check inputs
            var IcingaService = TryGetService(inputs["e"], inputs["host"], inputs["0"]);
            if (IcingaService is null)
                return new List<String>() { "Looks like " + inputs["0"] + " doesn't exist on " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
            inputs["0"] = IcingaService.ServiceName;
            var data = ParseIcingaAttributes(IcingaService.Attributes);
            var rerunCmd = data["RERUN_CMD"].ToString().Replace("\\ r", "\\r");
            if (rerunCmd == "")
                return new List<string>() { $"No rerunCMD on the serivce: {IcingaService.GetIcingaName()}" };
            if (!inputs.ContainsKey("s")) inputs["s"] = "1";
            if (!inputs.ContainsKey("1"))
                return new List<string>() { "You must provide a comment, like: \"" + BotTag + " OK(" + inputs["0"] + "#some comment" + (inputs.ContainsKey("s") ? ("#" + inputs["s"]) : "") + ")\"." };

            //Validate/run
            var validationFields = new List<String>() { "0", "1", "s", "anchorStr", "e", "validationkey" };
            SortedDictionary<String, String> validationInputs = new SortedDictionary<String, String>(inputs.Where(kv => validationFields.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value));

            if (validationInputs.ContainsKey("validationkey"))
            {
                //match with CurrentTasks
                var thisTuple = new Tuple<string, string>(validationInputs["validationkey"], JsonConvert.SerializeObject(validationInputs));
                if (CurrentTasks.Contains(thisTuple))
                {
                    CurrentTasks.Remove(thisTuple);
                    var dir = "C:\\LingoNightRider\\QRAsymphonyBot\\OK";
                    var logName = IcingaService.GetIcingaName().Replace("!", "-");
                    var CMD = rerunCmd + " --manualOK " + validationInputs["s"] + " --manualCom " + validationInputs["1"] + " --me " + user + " --directory \"" + dir + "\" --procLogFileName " + logName;
                    logName = Path.Join(dir.Replace("C:", "\\\\" + Dns.GetHostName()), logName);
                    RunOnRemote(user, "", CMD, logName, inputs["streamid"], "OKing taskId " + validationInputs["validationkey"]);
                    return new List<string>() { $"Will OK the job under taskId {validationInputs["validationkey"]}, and report when done." };
                }
                else
                    return new List<String>() { "Your request didn't match any active queries. Please try again without \"validationkey\" variable.", "Current keys: " + String.Join(", ", CurrentTasks.Select(t => t.Item1)) };
            }
            else
            {
                //add validation and request confirmation
                String validationKey = KeyGenerator.GetUniqueKey(16);
                validationInputs["validationkey"] = validationKey;
                String properRequest = BotTag + " ok(" + validationInputs["0"] + "#" + validationInputs["1"] + "#s=" + validationInputs["s"] + "#a=" + validationInputs["anchorStr"] + "#e=" + validationInputs["e"] + "#validationkey=" + validationKey + ")";
                CurrentTasks.Add(new Tuple<string, string>(validationKey, JsonConvert.SerializeObject(validationInputs)));
                return new List<String>() { "To validate your request, please send this message:", properRequest };
            }
        }

        /// <summary>
        /// Get jira tickets mathicng either anchor, or specific ticket key.
        /// </summary>
        /// <param name="input">Provide a for anchor string, or t for ticket key.</param>
        /// <param name="user">Ignored</param>
        /// <returns></returns>
        private List<String> GetJira(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            List<String> outputs = new List<string>();
            String jiraBaseURL = JiraURLBase + "/search?jql=";
            String JiraPostURL = "&validateQuery=false&pretty=1&verbose=1&fields=" + String.Join(",", JiraFields);
            String requestUrl;
            if (inputs.ContainsKey("t") || (inputs.ContainsKey("0") && inputs["0"].Contains("-")))
            {
                var ticket = inputs.ContainsKey("t") ? inputs["t"] : inputs["0"];
                requestUrl = jiraBaseURL + "id in (" + ticket + ")" + JiraPostURL;
                var getData = GetHttpAsync(requestUrl, false, JiraAuthorization).Result;
                var issues = ParseJiraResponseToTickets(getData);
                if (issues.ContainsKey(ticket))
                {
                    var jsonData = JsonDocument.Parse(JsonConvert.SerializeObject(issues[ticket]));
                    var fieldsAsDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonData.RootElement.GetProperty("fields").ToString());

                    var summary = jsonData.RootElement.GetProperty("fields").GetProperty("summary").ToString();
                    var description = jsonData.RootElement.GetProperty("fields").GetProperty("description").ToString();
                    //Comment
                    var jsonComments = jsonData.RootElement.GetProperty("fields").GetProperty("comment").GetProperty("comments");
                    var commentsAsList = JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(jsonComments.ToString());
                    var lastCommentsAuthor = JsonConvert.DeserializeObject<Dictionary<string, object>>(JsonConvert.SerializeObject(commentsAsList.Last()["author"]));
                    //Assignee
                    var assigneeAsDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(JsonConvert.SerializeObject(fieldsAsDict["assignee"]));
                    JsonElement assignee;
                    jsonData.RootElement.GetProperty("fields").TryGetProperty("assignee", out assignee);
                    String assigneeName = assignee.ValueKind.CompareTo(JsonValueKind.Null) > 0 ? assignee.GetProperty("displayName").ToString() : "Not assigned";
                    //Output message
                    outputs.Add("<i>" + jsonData.RootElement.GetProperty("self").ToString() + "</i> :");
                    outputs.Add("<b>summary:</b> " + HttpUtility.HtmlEncode(summary));
                    outputs.Add("<b>description:</b> " + HttpUtility.HtmlEncode(description));
                    outputs.Add("<b>assignee:</b> " + assigneeName);
                    outputs.Add("<b>last comment:</b> by " + lastCommentsAuthor["displayName"].ToString() + "<br/>" + HttpUtility.HtmlEncode(commentsAsList.Last()["body"].ToString()));
                }
                else
                    outputs.Add("Could not find " + ticket);
            }
            else
            {
                var anchor = ParseAnchor(inputs.ContainsKey("0") ? inputs["0"] : inputs["anchorStr"]);
                requestUrl = jiraBaseURL + "parent=" + JiraParentTicket + " AND created>='" + anchor.ToString("yyyy-MM-dd") + "' AND created<='" + anchor.AddTenor(new Tenor("2B"), "HE").ToString("yyyy-MM-dd") + " 00:00'" + JiraPostURL;
                var getData = GetHttpAsync(requestUrl, false, JiraAuthorization).Result;
                var issues = ParseJiraResponseToTickets(getData);
                if (issues.Count > 0)
                {
                    var filterSummary = "QRA_Batch_" + anchor.ToString("yyyyMMdd");
                    foreach (var i in issues)
                    {
                        var jsonData = JsonDocument.Parse(JsonConvert.SerializeObject(i.Value));//it's a Dict with Key being ticket number, and Value being the ticket object.
                        var summary = jsonData.RootElement.GetProperty("fields").GetProperty("summary").ToString();
                        if (summary.Contains(filterSummary))
                            outputs.Add(i.Key + ": " + summary);
                    }
                    if (outputs.Count == 0)
                        outputs.Add("Found no tickets with Summary containing: " + filterSummary);
                }
                else
                {
                    JsonElement error;
                    if (getData.RootElement.TryGetProperty("error", out error))
                        outputs.Add(error.ToString());
                    else
                        outputs.Add("Failed fetching jira tickets.");
                    Log.LogError("Failed fetching jira tickets with request: " + requestUrl);
                }
            }
            return outputs;
        }

        /// <summary>
        /// Get VictorOps oncall for current day, for predefined teams, or for one of them.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> VOPSOnCall(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            List<String> outputs = new List<string>();
            var selectedTeams = VictorOpsQRATeams;
            if (inputs.ContainsKey("0"))
            {
                if (inputs["0"] == "qra")
                    return selectedTeams.Keys.ToList();
                if (inputs["0"] == "teams")
                    return VictorOpsAllTeams.Keys.ToList();
                List<String> teams = inputs["0"].ToLower().Split("&").ToList();
                selectedTeams = VictorOpsQRATeams.Where(kv => teams.Contains(kv.Key.ToLower())).ToDictionary(kv => kv.Key, kv => kv.Value);
                if (selectedTeams.Count == 0)//try finding it in VOPS policies
                    selectedTeams = VictorOpsAllTeams.Where(kv => teams.Contains(kv.Key.ToLower())).ToDictionary(kv => kv.Key, kv => kv.Value);
            }
            if (inputs.ContainsKey("u"))
            {
                var rotationUser = GetVopsUser(inputs["u"].ToString());
                outputs.Add("<b>" + inputs["u"].ToString() + "</b><br/>" + String.Join("<br/>", rotationUser.Select(kv => "<i>" + kv.Key + "</i>: " + kv.Value)));
            }
            else
            {
                foreach (var team in selectedTeams)
                {
                    var onCallSchedule = GetVopsSchedule(team.Value);
                    if (onCallSchedule.ContainsKey("error"))
                        outputs.Add(onCallSchedule["error"].ToString());
                    else
                    {
                        if (onCallSchedule.ContainsKey("onCall"))
                        {
                            Dictionary<string, string> rotationUser = new Dictionary<string, string>();
                            if (onCallSchedule.ContainsKey("overrideOnCall"))
                                rotationUser = GetVopsUser(onCallSchedule["overrideOnCall"].ToString());
                            else
                                rotationUser = GetVopsUser(onCallSchedule["onCall"].ToString());
                            outputs.Add("<hr/><b>" + team.Key + "(" + onCallSchedule["rotationName"].ToString() + ")</b>:<br/>" + String.Join("<br/>", rotationUser.Select(kv => "<i>" + kv.Key + "</i>: " + kv.Value)));
                        }
                        else
                        {
                            outputs.Add("<hr/><b>" + team.Key + "</b>:<br/>No one currently on-call.");
                        }
                    }
                }
            }
            return outputs;
        }

        /// <summary>
        /// Send a VictorOps alert given vops user sender/recipient, subject, and text. Returns alert number.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> VOPSAlert(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            if (inputs.ContainsKey("3")) //Require 4 inputs: sender, recipient, subject, text
            {
                var alert = SentVopsAlert(inputs["0"], inputs["1"], inputs["2"], inputs["3"]);
                if (alert.ContainsKey("incidentNumber"))
                    return new List<string>() { $"Created alert {alert["incidentNumber"]} in victorOps, and sent it to {inputs["1"]}." };
                else
                {
                    var error = alert.ContainsKey("error") ? alert["error"].ToString() : "Unknown issue.";
                    Log.LogError($"Failed sending alert (sender: {inputs["0"]}, recipient: {inputs["1"]}, subject: {inputs["2"]}, text: {inputs["3"]}) to VOPS. Error:\n{error}");
                    return new List<string>() { "Alert couldn't be sent due to:", (error.Length > 128 ? error.Substring(0, 128) : error) + "..." };
                }
            }
            else
                return new List<string>() { "You need to provide sender, recipient, subject, text, in that order." };
        }

        /// <summary>
        /// Hand over on-call for a given team, from sender to recipient.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> VOPSHandover(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            if (inputs.ContainsKey("2")) //Require 4 inputs: sender, recipient, team
            {
                var handover = HandOverVops(inputs["0"], inputs["1"], inputs["2"]);
                string status;
                if (handover.ContainsKey("result"))
                    status = handover["result"].ToString();
                else
                {
                    status = handover.ContainsKey("error") ? handover["error"].ToString() : "Unknown issue.";
                    Log.LogError($"Failed to handover {inputs["2"]} from {inputs["0"]} to {inputs["1"]}. Error:\n{status}");
                    return new List<string>() { "Alert couldn't be sent due to:", (status.Length > 128 ? status.Substring(0, 128) : status) + "..." };
                }
                return new List<string>() { $"Status of handing over on-call from {inputs["0"]} to {inputs["1"]}: {status}." };
            }
            else
                return new List<string>() { "You need to provide sender, recipient, subject, text, in that order." };
        }

        /// <summary>
        /// Consume Sonic feeds into table.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> QuantWatch(String input, String user)
        {
            List<String> outputs = new List<string>();
            var data = RtDataDict.Values.Where(v => v.First().Value != "").ToList();
            var ids = RtDataDict.Where(v => v.Value.First().Value != "").ToList();
            if (data.Count == 0)
                return new List<string>() { "Nothing to show." };
            var fields = data.First().Keys.ToList();
            var qwData = new List<List<string>>() { fields };
            foreach (Dictionary<string, string> el in data)
            {
                var entry = new List<string>();
                foreach (string field in fields)
                    entry.Add(el.ContainsKey(field) ? el[field] : "");
                qwData.Add(entry);
            }
            outputs.Add(ListIntoHTMLTable(qwData));
            return outputs;
        }

        /// <summary>
        /// Add filter for icinga services polling for the source room.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> IcignaPolling(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            var acceptableInput0 = new List<string>() { "0", "CLEAR", "SAVE", "BATCH", "HELP", "RELOAD" };//SILENCE specific job with DISPLAYNAME=jobName filter
            //t for tag, b for EOD batch, i for all, not just isBatch.
            var streamKey = inputs["streamid"] + (inputs.ContainsKey("t") ? "#" + inputs["t"] : "") + (inputs.ContainsKey("0") && inputs["0"].ToUpper() == "BATCH" ? ("#" + IcingaPollingBatchFlag) : "");
            if (inputs.ContainsKey("0"))
            {
                if (!acceptableInput0.Contains(inputs["0"].ToUpper()))
                    return new List<string>() { "Unknown flag " + inputs["0"] + ". Acceptable flags: " + String.Join(",", acceptableInput0) + "." };
                if (inputs["0"] == "0")
                {
                    var matchingKeys = IcingaPollingSubscriptionFilters.Keys.Where(k => k.Contains(inputs["streamid"])).ToList();
                    foreach (var k in matchingKeys)
                        IcingaPollingSubscriptionFilters.Remove(k);
                    return new List<string>() { "Removed room from receiving Intraday Icinga status." };
                }
                if (inputs["0"].ToUpper() == "CLEAR")
                {
                    IcingaPollingSubscriptionFilters[streamKey] = new Dictionary<string, string>();
                    return new List<string>() { "Clean the filter for this room for receiving Intraday Icinga status." };
                }
                if (inputs["0"].ToUpper() == "RELOAD")
                {
                    string cusage = IcingaPollingContUsage;
                    if (inputs.ContainsKey("1"))
                        cusage = inputs["1"].ToUpper();
                    if (LoadIcingaPolling(IcingaPollingContName, cusage))
                        return new List<string>() { $"Reloaded filters from <b>{IcingaPollingContName}/{IcingaPollingContUsage}</b> container." };
                    else
                        return new List<string>() { $"Couldn't reload filters from <b>{IcingaPollingContName}/{IcingaPollingContUsage}</b> container." };
                }
                if (inputs["0"].ToUpper() == "SAVE")
                {
                    string cusage = IcingaPollingContUsage;
                    if (inputs.ContainsKey("1"))
                        cusage = inputs["1"].ToUpper();
                    if (SaveIcingaPolling(IcingaPollingContName, cusage))
                        return new List<string>() { "Saved current IcingaPollingSubscriptionFilters into " + IcingaPollingContName + "/" + cusage + "." };
                    else
                        return new List<string>() { "Failed to save current IcingaPollingSubscriptionFilters into " + IcingaPollingContName + "/" + cusage + "." };
                }
                if (inputs["0"].ToUpper() == "HELP")
                {
                    var help = new List<string>() { $"Current filter, if saved, is in <i>{IcingaPollingContName}/{IcingaPollingContUsage}</i> container." };
                    help.Add("<b>Your stream is:</b> " + streamKey);
                    help.Add("<b>Current filter:</b>");
                    var matchingKeys = IcingaPollingSubscriptionFilters.Keys.Where(k => k.Contains(inputs["streamid"])).ToList();
                    foreach (var k in matchingKeys)
                    {
                        help.Add("-->" + k + ":");
                        help.AddRange(IcingaPollingSubscriptionFilters[k].Select(kv => "...|___>" + kv.Key + "=" + kv.Value).ToList());
                    }
                    help.Add("<b>Examples:</b>");
                    help.Add(RobotFuncsExamples["IPOLL"]);
                    return help;
                }
            }
            List<String> outputs = new List<string>();

            //Parse potential start/stop input
            if (inputs.ContainsKey("start") || inputs.ContainsKey("stop"))
            {
                if (!inputs.ContainsKey("start")) inputs["start"] = "7:00";
                if (!inputs.ContainsKey("stop")) inputs["stop"] = "19:00";
                if (ParseTimeIntoHHMM(inputs["start"], out string timeStart) && ParseTimeIntoHHMM(inputs["stop"], out string timeStop))
                    streamKey += "@" + timeStart + "-" + timeStop;
                else
                    outputs.Add("Warning: couldn't parse your start/stop input!");
            }
            //put filter into the IcingaPollingSubscriptionFilters dictionary
            var roomName = GetRoomName(inputs["streamid"]);
            if (!IcingaPollingSubscriptionFilters.ContainsKey(streamKey))
                IcingaPollingSubscriptionFilters[streamKey] = new Dictionary<string, string>();
            if (inputs.ContainsKey("f"))
            {
                var filtersPairs = inputs["f"].Split("&").ToList().Select(f => f.Split("$").ToList()).ToList();
                if (IcingaPollingSubscriptionFilters[streamKey].Count == 0)
                    IcingaPollingSubscriptionFilters[streamKey] = filtersPairs.ToDictionary(f => f[0], f => f[1]);
                else
                    filtersPairs.ToDictionary(f => f[0], f => f[1]).ToList().ForEach(x => IcingaPollingSubscriptionFilters[streamKey][x.Key] = x.Value);
            }
            outputs.Add("This room will receive info about erroneous Icinga services on " + (streamKey.Contains("#" + IcingaPollingBatchFlag) ? IcingaDefaultHost : IcingaDefaultPollingHost) + " every " + IcingaPollingFrequency.ToString() + " minutes.");
            outputs.Add("<b>Current " + (streamKey.Contains("#" + IcingaPollingBatchFlag) ? "EOD batch" : "intraday") + " IcingaPolling filter for this room:</b>");
            outputs.AddRange(IcingaPollingSubscriptionFilters[streamKey].Count > 0 ? IcingaPollingSubscriptionFilters[streamKey].Select(kv => kv.Key + "=" + kv.Value).ToList() : new List<string>() { "No filter, reading all services from " + IcingaDefaultPollingHost });
            return outputs;
        }

        /// <summary>
        /// Use Icinga details to rerun CRITICAL job.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> Rerun(String input, String user)
        {
            //rerun(superRisk#a=20200616#e=PROD#args=--clones None)
            var inputs = ParseRobotInput(input);
            string room = inputs["streamid"];
            inputs["e"] = inputs["e"].ToUpper();
            //Check inputs
            var IcingaService = TryGetService(inputs["e"], inputs["host"], inputs["0"]);
            if (IcingaService is null)
                return new List<String>() { "Looks like " + inputs["0"] + " doesn't exist on " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
            inputs["0"] = IcingaService.ServiceName;
            var data = ParseIcingaAttributes(IcingaService.Attributes);
            var server = inputs.ContainsKey("server") ? inputs["server"] : data["SERVER"].ToString();
            if (server == "\"\"") server = "";
            var rerunCmd = data["RERUN_CMD"].ToString().Replace("\\ r", "\\r");
            if (rerunCmd == "")
                return new List<string>() { $"No rerunCMD on the serivce: {IcingaService.GetIcingaName()}" };
            if (inputs.ContainsKey("1"))
            {
                if (inputs["1"] != "")
                {
                    var rerunCmdArray = rerunCmd.Split("--");
                    var rerunCmdOverwrite = inputs["1"].Split("&").Select(a => new Tuple<string, string>(a.Split("$")[0], a.Split("$")[1])).ToList();
                    var rerunArgsOverwrite = rerunCmdOverwrite.Select(t => t.Item1).ToList();
                    var rerunCmdOut = "";
                    foreach (var arg in rerunCmdArray)
                    {
                        var justArg = arg.Split(" ")[0];
                        bool isOverwritten = rerunArgsOverwrite.Contains(justArg);
                        if (isOverwritten)
                            rerunCmdOut += " --" + justArg + " " + rerunCmdOverwrite.Where(t => t.Item1 == justArg).Select(t => t.Item2).First();
                        else
                            rerunCmdOut += (rerunCmdOut == "" ? "" : " --") + arg;
                    }
                    rerunCmd = rerunCmdOut;
                }
            }
            else
                inputs["1"] = "";
            var validationFields = new List<String>() { "0", "1", "anchorStr", "e", "validationkey" };
            SortedDictionary<String, String> validationInputs = new SortedDictionary<String, String>(inputs.Where(kv => validationFields.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value));
            if (validationInputs.ContainsKey("validationkey"))
            {
                //match with CurrentTasks
                var thisTuple = new Tuple<string, string>(validationInputs["validationkey"], JsonConvert.SerializeObject(validationInputs));
                if (CurrentTasks.Contains(thisTuple))
                {
                    CurrentTasks.Remove(thisTuple);
                    string logfile = "\\\\" + Dns.GetHostName() + "\\LingoNightRider\\QRAsymphonyBot\\RERUN\\" + IcingaService.GetIcingaName().Replace("!", "-") + ".log";
                    if (File.Exists(logfile)) File.Delete(logfile);//remove logFile, so it only has the current info
                    logfile = data.ContainsKey("PROCLOG") ? data["PROCLOG"].ToString() : logfile;
                    _ = SendAsHtmlStream(room, new List<String>() { $"Will execute a rerun of {IcingaService.GetIcingaName()} on {server}.", $"Check {logfile} for progress, or follow it in Icinga." });
                    RunOnRemote(user, server, rerunCmd, logfile, inputs["streamid"], "Rerunning taskId " + validationInputs["validationkey"]);
                    return new List<string>() { $"Will rerun the job under taskId {validationInputs["validationkey"]}, and report when done." };
                }
                else
                    return new List<String>() { "Your request didn't match any active queries. Please try again without \"validationkey\" variable.", "Current keys: " + String.Join(", ", CurrentTasks.Select(t => t.Item1)) };
            }
            else
            {
                //add validation and request confirmation
                String validationKey = KeyGenerator.GetUniqueKey(16);
                validationInputs["validationkey"] = validationKey;
                String properRequest = BotTag + " rerun(" + validationInputs["0"] + "#" + validationInputs["1"] + (inputs.ContainsKey("server") ? ("#server=" + inputs["server"]) : "") + "#a=" + validationInputs["anchorStr"] + "#e=" + validationInputs["e"] + "#validationkey=" + validationKey + ")";
                CurrentTasks.Add(new Tuple<string, string>(validationKey, JsonConvert.SerializeObject(validationInputs)));
                return new List<String>() { "To validate your request, please send this message:", properRequest };
            }
        }

        /// <summary>
        /// For job on ERROR, throw alert.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> ThrowBlame(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            string room = inputs["streamid"];
            inputs["e"] = inputs["e"].ToUpper();
            var IcingaService = TryGetService(inputs["e"], inputs["host"], inputs["0"]);
            if (IcingaService is null)
                return new List<String>() { "Looks like " + inputs["0"] + " doesn't exist on " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
            if (!IcingaService.RuntimeAttributes.LastCheckResult.ContainsKey("state") || Int32.Parse(IcingaService.RuntimeAttributes.LastCheckResult["state"].ToString().Replace(".0", "")) != 2)
                return new List<String>() { "Looks like " + inputs["0"] + " is not on ERROR on host " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
            inputs["0"] = IcingaService.ServiceName;
            var data = ParseIcingaAttributes(IcingaService.Attributes);
            string logfile = "\\\\" + Dns.GetHostName() + "\\LingoNightRider\\QRAsymphonyBot\\THROWBLAME\\" + IcingaService.GetIcingaName().Replace("!", "-") + ".log";
            string cmd = $"\\\\danskenet.net\\markets\\superfly\\productionreports\\ApocTools.py throwBlame --reports {inputs["0"]} --anchor {inputs["anchorStr"]}" 
                        + (inputs.ContainsKey("d")?(" --delay "+ inputs["d"]) :"") + " --logfile " + logfile + " --ICINGAENV " + inputs["e"];
            String validationKey = KeyGenerator.GetUniqueKey(16);
            RunOnRemote(user, "", cmd, logfile, room, "Throwing blame under taskId " + validationKey);
            return new List<string>() { $"Will throw alert for {IcingaService.GetIcingaName()} on {Dns.GetHostName()} under taskId {validationKey}, and report when done." };

        }

        /// <summary>
        /// Add pisins unitrisk for specified riskviews (or defaults from UNITRISKCALC lingo).
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> AddUnitRisk(String input, String user)
        {
            var inputs = ParseRobotInput(input);
            if (!inputs.ContainsKey("0"))
                return new List<String>() { "Please provide PISINs!"};
            string logfile = "\\\\" + Dns.GetHostName() + "\\LingoNightRider\\QRAsymphonyBot\\AddUnitRisk.log";
            string cmd = "--run UNITRISKCALC --taskusage eod --pisins " + inputs["0"] + (inputs.ContainsKey("1") ? " --riskviews" + inputs["1"] : "");
            cmd += " --logfile " + logfile;
            RunOnRemote(user, "", cmd, logfile, inputs["streamid"], "Finished adding UnitRisk for " + inputs["0"], "\\\\danskenet.net\\markets\\superfly\\Executables\\LingoNightRider\\LingoNightrider.exe");
            return new List<string>() { $"Will try adding your isins to UnitRisk, and report when done. See logfile: " + logfile};
        }

        /// <summary>
        /// For testing purposes.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private List<String> Test(String input, String user)
        {
            
            var inputs = ParseRobotInput(input);
            RunOnRemote("B94628", "", "ping", "C:\\temp\\log.log", inputs["streamid"], "", @"C:\WINDOWS\system32\cmd.exe");
            return new List<String>();

            var messageOut = new List<String>();
            var IcingaService = TryGetService(inputs["e"], inputs["host"], inputs["0"]);
            if (IcingaService is null)
                return new List<String>() { "Looks like " + inputs["0"] + " doesn't exist on " + inputs["host"] + " in Icinga " + inputs["e"] + "." };
            var data = ParseIcingaAttributes(IcingaService.Attributes);
            var server = data["SERVER"].ToString();
            messageOut.Add($"Found out that {IcingaService.GetIcingaName()} runs on {server}.");
            string streamKey = inputs.ContainsKey("streamid") ? inputs["streamid"] : "odsgdbfdgsdgfd34ermewf";
            if (inputs.ContainsKey("stop"))
            {
                string timeStop = "";
                if (ParseTimeIntoHHMM(inputs["stop"], out timeStop))
                    streamKey += "@" + timeStop;
                messageOut.Add("Stream: " + streamKey);
            }
            return messageOut;
            //var inputs = ParseRobotInput(input);
            //string logfile = "\\\\" + inputs["0"] + "\\LingoNightRider\\RunningTest.log";
            //Task.Run(() => RunOnRemote(user, inputs["0"], inputs["1"], logfile, inputs["streamid"], "Your test"));
            //return new List<string>() { $"Executing: \"{inputs["1"]}\" under taskId {KeyGenerator.GetUniqueKey(16)}. Will shout when done" };
        }

        #endregion
    }

    /// <summary>
    /// Html formatted message creation, and conversion into Symphony message.
    /// </summary>
    public class HtmlMessage : ISymphonyMessage
    {
        private readonly string _htmlString;


        private HtmlMessage(string htmlString, string data)
        {
            _htmlString = htmlString;
            Data = data;
        }

        public string FormatToString()
        {
            return _htmlString;
        }

        public static ISymphonyMessage CreateMessage(string html, object data) => new HtmlMessage(html, JsonConvert.SerializeObject(data ?? new object(), new JsonSerializerSettings
        {
            ContractResolver = new CamelCasePropertyNamesContractResolver()
        }));


        public string Data { get; set; }
        public List<ISymphonyMessageItem> MessageItems { get; set; }
    }

    /// <summary>
    /// Alphanumeric key generator.
    /// </summary>
    public class KeyGenerator
    {//https://stackoverflow.com/questions/1344221/how-can-i-generate-random-alphanumeric-strings
        internal static readonly char[] chars =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

        public static string GetUniqueKey(int size)
        {
            byte[] data = new byte[4 * size];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(size);
            for (int i = 0; i < size; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % chars.Length;

                result.Append(chars[idx]);
            }

            return result.ToString();
        }
    }
}
