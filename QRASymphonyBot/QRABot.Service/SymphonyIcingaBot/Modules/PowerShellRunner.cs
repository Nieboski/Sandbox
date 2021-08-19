using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace QRASymphonyBot
{
    class PowerShellRunner
    {
        #region Members
        private PSCredential Creds = null;
        #endregion

        #region C-tor
        public PowerShellRunner() { }
        public PowerShellRunner(string base64credentials) { this.SetCredentials(base64credentials); }
        #endregion

        public async Task<Tuple<bool,List<String>>> RunCmd(string command, string serverAlias="")
        {
            List<String> outList = new List<String>();
            bool retSucc = false;
            try
            {
                Runspace rs = RunspaceFactory.CreateRunspace();
                rs.Open();
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;
                    var scriptBlock = ScriptBlock.Create(command);
                    ps.AddCommand("Invoke-Command").AddArgument(scriptBlock);
                    if (serverAlias != "")
                        ps.AddParameter("ComputerName", Dns.GetHostEntry(serverAlias).HostName).AddParameter("Credential", Creds).AddParameter("Authentication", "Credssp");
                    var ret = await ps.InvokeAsync();

                    if (ps.HadErrors && ret.Count == 0)
                        outList.Add(ps.Streams.Error.ElementAt(0).Exception.Message); //TODO Running python via Invoke-Commnad returns HasErrors==true, but not clear why.
                    else
                    {
                        retSucc = true;
                        foreach (var o in ret)
                            outList.Add(o.ToString());
                    }
                }
                rs.Close();
            }
            catch (Exception ex)
            {
                retSucc = false;
                outList.Add(ex.Message);
            }
            return new Tuple<bool, List<String>>(retSucc, outList);
        }

        private void SetCredentials(string base64credentials)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64credentials);
            string[] creds = (Encoding.UTF8.GetString(base64EncodedBytes)).Split(":");
            var secureString = new SecureString();
            Array.ForEach(creds[1].ToCharArray(), secureString.AppendChar);
            Creds = new PSCredential(creds[0], secureString );
        }
    }
}
