using ART.SymphonyClient.Exceptions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using System.Text;
using System.Threading;
using Microsoft.Extensions.Configuration;
using SuperFlySharp.Data;
using SuperFlySharp.Data.Container;

namespace QRASymphonyBot
{
    /// <summary>
    /// Main bot service.
    /// </summary>
    public class QRASymphonyBot : IHostedService
    {
        #region Members
        private readonly ILogger<QRASymphonyBot> Logger;
        private readonly IConfiguration Configuration;
        private readonly IRtDataProvider RtDataSource;
        private readonly IDataStore<IDBDataLocation> DBSource;
        #endregion

        /// <summary>
        /// Construct the bot object.
        /// </summary>
        /// <param name="config">Config for Symphony communciation, victorOps API, Icinga API, logger, and jira.</param>
        /// <param name="logger"></param>
        /// <param name="rtDataSource"></param>
        /// <param name="dbSource"></param>
        public QRASymphonyBot(IConfiguration config, ILogger<QRASymphonyBot> logger, IRtDataProvider rtDataSource, IDataStore<IDBDataLocation> dbSource)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            Configuration = config ?? throw new ArgumentNullException(nameof(config));
            RtDataSource = rtDataSource ?? throw new ArgumentNullException(nameof(rtDataSource));
            DBSource = dbSource ?? throw new ArgumentNullException(nameof(dbSource));
        }

        #region Helper methods
        /// <summary>
        /// Initialize the relevant bot data, and run.
        /// </summary>
        /// <returns></returns>
        public async Task InitAndRun()
        {
            Directory.CreateDirectory(@"C:\LingoNightRider\QRAsymphonyBot\OK");//Ensure local dir
            Directory.CreateDirectory(@"C:\LingoNightRider\QRAsymphonyBot\THROWBLAME");//Ensure local dir
            Directory.CreateDirectory(@"C:\LingoNightRider\QRAsymphonyBot\RERUN");//Ensure local dir
            Configure();


            //Load QRA group
            var grp = LoadContainer("GRP_QUANTIT", "GROUP");
            var ElevatedUsers = grp != null ? grp.Select(l => l.First()).ToList() : new List<string>() { Environment.UserName };

            //Symphony bot
            Logger.LogInformation("Create SymphonyIcingaBot");
            SymphonyIcingaBot TheBot = new SymphonyIcingaBot(Configuration, Logger, RtDataSource);
            TheBot.AddElevatedUsers(ElevatedUsers);
#if DEBUG
            //Extra flags for DEBUG mode, to minimize the incoming messages.
            //Set filter on Symphony to only react on current user requests.
            TheBot.SetSymphonyUserFilter(Environment.UserName);
            TheBot.SetBotTag("!B");
            TheBot.SetRtDataId("QRABot.Test.*");
            Logger.LogInformation("Mode=Debug, will only listen to Symphony from " + Environment.UserName);
#endif
            Logger.LogInformation("RunBotSafely");
            await RunBotSafely(TheBot);
        }

        /// <summary>
        /// Catch Symphony Client issues for Symphony bot, and restart on those. Crash on others.
        /// </summary>
        /// <param name="bot">SymphonyIcingaBot client</param>
        /// <param name="restartCount">current restart count</param>
        /// <param name="restartMax">max number of restarts allowed</param>
        /// <returns></returns>
        private async Task RunBotSafely(SymphonyIcingaBot bot, int restartCount = 0, int restartMax = 5)
        {
            while (true)
            {
                try
                {
                    await bot.RunClient();
                }
                catch (ClientException ce)//potentialy bogus exceptions from Symphony client (backend restart, etc)
                {
                    Logger.LogWarning(ce, "Restarting Symphony Client due to ClientException. {ErrorMessage}, {InnerErrorMessage}", ce.Message, ce.InnerException?.Message);
                    System.Threading.Thread.Sleep(2000);
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "Symphony API threw an Exception: {ErrorMessage}", ex.Message);
                    restartCount++;
                    if (restartCount <= restartMax)
                    {
                        Logger.LogInformation("Will restart for the " + restartCount.ToString() + ". time out of " + restartMax.ToString() + " allowed times.");
                        System.Threading.Thread.Sleep(2000);
                    }
                    else
                    {
                        throw new NotSupportedException("Limit (" + restartMax.ToString() + ") of restarts for SymphonyBot reached. Will crash now.\nFull exception:\n" + ex.ToString());
                    }
                }
            }
        }

        /// <summary>
        /// Load configuration json into Configruation Dictionary.
        /// </summary>
        private void Configure()
        {
#if DEBUG
            var base64credentials = Configuration["GLOBAL:credentialsDebug"];
#else
            var base64credentials = Configuration["GLOBAL:credentials"];
#endif
            var base64EncodedBytes = Convert.FromBase64String(base64credentials);
            string[] creds = (Encoding.UTF8.GetString(base64EncodedBytes)).Split(":");
            Configuration["SYMPHONY:ProxyUsername"] = creds[0];
            Configuration["SYMPHONY:ProxyPassword"] = creds[1];
        }
                        

        /// <summary>
        /// Load container into a DataTable.
        /// </summary>
        private List<List<String>> LoadContainer(String contId, String contUsage)
        {
            try
            {
                var tmp = DBSource.LoadAs<IContainer>(new DBDataLocation(contId, contUsage)).AsMatrix;
                return tmp.Select(l => l.ToList()).ToList();
            }
            catch (Exception Ex)
            {
                Logger.LogError("In LoadContainer, failed loading container: " + contId + " / " + contUsage + ", Cought: " + Ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Called by the hosting framework on startup
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task StartAsync(CancellationToken cancellationToken)
        {
            var _= new Timer((e) => { InitAndRun();}, null, 1, Timeout.Infinite );
            return Task.CompletedTask;
        }

        /// <summary>
        /// Called by the hosting framework on service shutdown
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task StopAsync(CancellationToken cancellationToken)
        {
            Logger.LogInformation("Calling StopAsync.");
            return Task.CompletedTask;
        }

        #endregion
    }

}
