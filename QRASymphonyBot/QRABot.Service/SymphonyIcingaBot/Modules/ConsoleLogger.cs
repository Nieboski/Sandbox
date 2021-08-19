using Microsoft.Extensions.Logging;
using System;

namespace QRASymphonyBot
{
    class ConsoleLogger : ILogger
    {
        private readonly bool Enabled = true;
        private readonly bool Debug = false;
        private readonly String TimestampFormat = "yyyy-MM-dd HH:mm:ss";
        public ConsoleLogger()
        {
        }

        public ConsoleLogger(bool debug) => Debug = debug;

        private string Timestamp(DateTime time)
        {
            return time.ToString(TimestampFormat);
        }

        IDisposable ILogger.BeginScope<TState>(TState state)
        {
            throw new NotImplementedException();
        }

        bool ILogger.IsEnabled(LogLevel logLevel)
        {
            return Enabled;
        }

        void ILogger.Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if ((logLevel>=LogLevel.Information || Debug) && logLevel>LogLevel.Trace)
                Console.WriteLine(Timestamp(DateTime.Now) + " " + logLevel + " " + eventId.ToString() + " " + state.ToString());
        }

        public void Log(LogLevel logLevel, String message)
        {
            if ((logLevel >= LogLevel.Information || Debug) && logLevel > LogLevel.Trace)
                Console.WriteLine(Timestamp(DateTime.Now) + " " + logLevel + " " +  message);
        }
    }
}
