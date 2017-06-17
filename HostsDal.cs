using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml;
using System.Runtime.InteropServices;

namespace HostsMate
{
    public class HostsDal
    {
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern UInt32 DnsFlushResolverCache();

        public static readonly string HostsPath = Path.Combine( Environment.SystemDirectory,@"drivers\etc\hosts");


        /// <summary>
        /// 匹配被注释的Hosts记录的正则
        /// </summary>
        public static readonly Regex RegItem =
            new Regex(@"^\s*#?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([^\s]+)\s*#?(.*)$", RegexOptions.Compiled);

        /// <summary>
        /// The default comments
        /// </summary>
        public static readonly string DefaultComments = @"# Copyright (c) 1993-1999 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host
";

        public List<HostItem> GetHosts()
        {
            if (File.Exists(HostsPath))
            {
                using (StreamReader reader = new StreamReader(HostsPath, Encode))
                {
                    List<HostItem> items = new List<HostItem>();
                    string line;

                    //// Ignore default comments.
                    for (int i = 0; i < 17; i++ )
                    {
                        line = reader.ReadLine();
                    }

                    while (!reader.EndOfStream)
                    {
                        line = reader.ReadLine().Trim();

                        if (string.IsNullOrEmpty(line))
                        {
                            if (items.Count > 0)
                            {
                                items[items.Count - 1].AddLine = true;
                            }

                            continue;
                        }

                        if (line.StartsWith("#"))
                        {
                            HostItem item = new HostItem(line);
                            items.Add(item);

                            continue;
                        }

                        Match match = RegItem.Match(line);
                        if (match.Success)
                        {
                            string ip = match.Result("$1");
                            string name = match.Result("$2");
                            string desc = match.Result("$3");

                            HostItem item = new HostItem(ip, name, desc, false);
                            items.Add(item);
                        }
                    }
                    return items;
                }
            }
            return null;
        }

        /// <summary>
        /// Save the new host file。
        /// </summary>
        /// <param name="name"></param>
        /// <param name="items">The new hosts</param>
        public void Save(List<HostItem> items)
        {
            using (StreamWriter sw = new StreamWriter(HostsPath, false, Encode))
            {
                // Add default comments.
                sw.WriteLine(DefaultComments);

                foreach (HostItem item in items)
                {
                    sw.WriteLine(item.ToString());
                }

                sw.Close();
            }

            DnsFlushResolverCache();
        }


        /// <summary>
        /// The hosts encode
        /// </summary>
        public static Encoding Encode
        {
            get
            {
                return Encoding.GetEncoding("GB2312");
            }
        }
    }
}
