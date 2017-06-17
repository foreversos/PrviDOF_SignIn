using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HostsMate
{
    /// <summary>
    /// 
    /// </summary>
    [Serializable]
    public class HostItem
    {
        public HostItem(string comment)
        {
            this.Comment = comment;
        }

        public HostItem(string ip, string name, string desc, bool addLine)
        {
            IP = ip;
            Name = name;
            Description = desc;
            AddLine = addLine;
        }

        /// <summary>
        /// IP
        /// </summary>
        public string IP { get; set; }

        /// <summary>
        /// domain name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The comment items for host record.
        /// </summary>
        public string Comment { get; set; }

        /// <summary>
        /// comment at end
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// is commeted.
        /// </summary>
        public bool IsComment { 
            get 
            { 
                if(string.IsNullOrWhiteSpace(this.Comment))
                {
                    return false;
                } 
                else
                {
                    return true;
                }
            } 
        }

        /// <summary>
        /// add empty line after item.
        /// </summary>
        public bool AddLine { get; set; }

        /// <summary>
        /// tostring
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            if(IsComment)
            {
                return Comment;
            }

            if (string.IsNullOrEmpty(IP) || string.IsNullOrEmpty(Name))
            {
                return string.Empty;
            }

            string item = string.Format("{0} {1}",
                IP.Trim().PadRight(17),
                Name.Trim().PadRight(40)
                );

            if (!string.IsNullOrEmpty(Description))
            {
                item = string.Format("{0} #{1}", item, Description.Trim());
            }

            if (AddLine)
            {
                item += "\r\n";
            }

            return item;
        }
    }
}
