using DXFLogin.Properties;
using HostsMate;
using Microsoft.Win32;
using MySql.Data.MySqlClient;
using RSAPwd;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DXFLogin
{
    class DNFLoginReg
    {
        public string ServerIP { get; set; }
        public string DB_Name { get; set; }
        public string DB_Pwd { get; set; }

        public DNFLoginReg()
        {
            this.ServerIP = "192.168.0.107";
            this.DB_Name = "game";
            this.DB_Pwd = "u!m^4%zg";
        }

        public bool Reg(string userName, string pwd)
        {

            string connectionstring = string.Format("Server={0};Database=mysql;Uid={1};Pwd={2};SslMode = Preferred;", this.ServerIP, this.DB_Name, this.DB_Pwd);
            using (MySqlConnection connection = new MySqlConnection(connectionstring))
            {
                connection.Open();

                string sql = string.Format("select uid from d_taiwan.accounts where accountname='{0}'", userName);
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    object row = command.ExecuteScalar();
                    if (row != null)
                    {
                        return false;
                    }
                }

                int uid = 1;
                sql = string.Format("select * from d_taiwan.accounts order by UID desc limit 1");
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            uid = Convert.ToInt32(reader[0]);
                            uid++;
                        }
                    }
                }

                string regdb = "100000";     //注册赠送D币数量
                string regdd = "100000";		//注册赠送D点数量

                string pwdMD5 = GetMD5(pwd);
                RunSql(string.Format("insert into d_taiwan.accounts (uid,accountname,password) VALUES ('{0}','{1}','{2}')", uid, userName, pwdMD5), connection);
                RunSql(string.Format("insert into d_taiwan.limit_create_character (m_id) VALUES ('{0}')", uid), connection);
                RunSql(string.Format("insert into d_taiwan.member_info (m_id,user_id) VALUES ('{0}','{1}')", uid, uid), connection);
                RunSql(string.Format("insert into d_taiwan.member_join_info (m_id) VALUES ('{0}')", uid), connection);
                RunSql(string.Format("insert into d_taiwan.member_miles (m_id) VALUES ('{0}')", uid), connection);
                RunSql(string.Format("insert into d_taiwan.member_white_account (m_id) VALUES ('{0}')", uid), connection);
                RunSql(string.Format("insert into taiwan_login.member_login (m_id) VALUES ('{0}')", uid), connection);
                RunSql(string.Format("insert into taiwan_billing.cash_cera (account,cera,mod_date,reg_date) VALUES ('{0}','{1}',NOW(),NOW())", uid, regdb), connection);
                RunSql(string.Format("insert into taiwan_billing.cash_cera_point (account,cera_point,reg_date,mod_date) VALUES ('{0}','{1}',NOW(),NOW())", uid, regdd), connection);
                RunSql(string.Format("insert into taiwan_cain_2nd.member_avatar_coin (m_id) VALUES ('{0}')", uid), connection);
                return true;
            }


        }

        private void RunSql(string sql, MySqlConnection connection)
        {
            using (MySqlCommand command = new MySqlCommand(sql, connection))
            {
                command.ExecuteNonQuery();
            }
        }

        public int Login(string userName, string pwd)
        {
            string connectionstring = string.Format("Server={0};Database=mysql;Uid={1};Pwd={2};SslMode = Preferred;", this.ServerIP, this.DB_Name, this.DB_Pwd);
            using (MySqlConnection connection = new MySqlConnection(connectionstring))
            {
                connection.Open();

                int uid = -1;

                string pwdMD5 = GetMD5(pwd);
                string sql = string.Format("select UID from d_taiwan.accounts where accountname='{0}' and password='{1}'", userName, pwdMD5);
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        
                        while (reader.Read())
                        {
                            uid = Convert.ToInt32(reader[0]);
                            break;
                        }
                    }
                }

                if (uid > -1)
                {
                    RunSql(string.Format("update d_taiwan.limit_create_character set count=0 where m_id='{0}'", uid), connection);//取消角色创建限制
                }

                return uid;
            }
        }

        public void WriteHosts()
        {
            var name = "start.dnf.tw";
            var hostdal = new HostsDal();
            var list = hostdal.GetHosts();
            bool have = false;
            foreach (HostItem item in list)
            {
                have = item.Name == name;
                if (have)
                {
                    item.IP = this.ServerIP;
                    break;
                }
            }

            if (!have) list.Add(new HostItem(this.ServerIP, name, "", false));
            hostdal.Save(list);
        }



        public string GetLoginBase64(int userId)
        {
            string privateKey = Encoding.UTF8.GetString(Resources.privatekey);
            RSAParameters p = RSAHelper.ConvertFromPemPrivateKey(privateKey);
            string start = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00";
            string end = "010101010101010101010101010101010101010101010101010101010101010155914510010403030101";
            string id = start + userId.ToString("X8") + end;
            int l = id.Length;
            byte[] bufId = (new BigInteger(id, 16)).getBytes();
            byte[] mm = DataTranslate.HexStringToByte(id);
            byte[] bufCode = RSAHelper.RsaDecrypt(mm, p.D, p.Modulus);
            string base64 = Convert.ToBase64String(bufCode);
            return base64;
        }


        private string GetMD5(string myString)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] fromData = System.Text.Encoding.ASCII.GetBytes(myString);
            byte[] targetData = md5.ComputeHash(fromData);
            string byte2String = null;

            for (int i = 0; i < targetData.Length; i++)
            {
                byte2String += targetData[i].ToString("x2");
            }

            return byte2String;
        }

    }
}