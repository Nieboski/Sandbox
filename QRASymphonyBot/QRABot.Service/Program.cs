using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using SuperFly.Framework.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SuperFlySharp.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using SuperFlySharp.Model;
using SuperFlySharp.Trade;
using System.Text;

namespace QRABot.Web
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); //to handle incoming sonic data.
            Environment.ExitCode = SuperFly.Framework.Hosting.Host.RunDefault(args, builder =>
            {
                builder.ConfigureLogging(lb => lb.AddConfiguration(new ConfigurationBuilder().AddJsonFile("config/hostsettings.json", false).Build()));
                builder.ConfigureAppConfiguration(lb => lb.AddConfiguration(new ConfigurationBuilder().AddJsonFile("config/botsettings.json", false).Build()));
                builder.ConfigureServices((ctx, sc) =>
                {
                    sc
                        // load superfly thread-safely. 
                        .UseSuperFly()

                        // add the hosted (web) service
                        .AddHostedService<QRASymphonyBot.QRASymphonyBot>()

                        // add forwarding for proxies
                        .Configure<ForwardedHeadersOptions>(options => options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);
                });
            });
        }


        //public static void Main(string[] args)
        //{
        //    Environment.ExitCode = SuperFly.Framework.Hosting.Host.RunDefault(args, builder =>
        //    {
        //    builder.ConfigureWebHostDefaults(wb =>
        //    {
        //        var config = new ConfigurationBuilder().AddJsonFile("config/hostsettings.json", false).Build();
        //        wb.UseConfiguration(config);
        //        wb.UseStartup<Startup>();

        //    });
        //    builder.ConfigureServices((ctx, sc) =>
        //    {

        //    sc
        //        .UseSuperFly()

        //             Add servicebase components such as IBus and ITracer.
        //                .AddServiceBaseBus(withTracing: true)

        //             Add the actual interface that performs the business logic
        //               //.AddSingleton<INumberChruncher>(x => new Multiplier(12))
                        

        //                 add the hosted(web) service
        //               //.AddHostedService<ExampleService.ExampleService>();
        //        });
        //    });
        //}
    }

    //public class SuperFlyTestSession : ISuperFlySession
    //{

    //    public SuperFlyTestSession()
    //    {
    //        var session = new StandardSuperFlySession();
    //        TickingModelSource = session.TickingModelSource;
    //        ModelSource = session.ModelSource;
    //        RtDataProvider = session.RtDataProvider;
    //        DataStore = new LockedDataBaseStoreStuff(session.DataStore);
    //        TradeUtils = session.TradeUtils;
    //    }

    //    public ITickingModelSource TickingModelSource { get; set; }

    //    public IDatabaseModelSource ModelSource { get; set; }

    //    public IRtDataProvider RtDataProvider { get; set; }

    //    public IDataStore<IDBDataLocation> DataStore { get; set; }

    //    public ITradeUtils TradeUtils { get; set; }
    //}

    //public class LockedDataBaseStoreStuff : IDataStore<IDBDataLocation>
    //{

    //    private static readonly object MyLock = new object { };
    //    private readonly IDataStore<IDBDataLocation> dataStore;

    //    public LockedDataBaseStoreStuff(IDataStore<IDBDataLocation> dataStore)
    //    {
    //        this.dataStore = dataStore;
    //    }

    //    public U LoadAs<U>(IDBDataLocation source) where U : IDataObject
    //    {

    //        lock (MyLock)
    //            return dataStore.LoadAs<U>(source);
    //    }

    //    public void Save(IDataObject dataObject, IDBDataLocation target)
    //    {
    //        throw new NotImplementedException();
    //    }
    //}

}
