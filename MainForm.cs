using System;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;

namespace DXFLogin
{
    public partial class MainForm : Form
    {
        private DNFLoginReg loginManager = new DNFLoginReg();

        public MainForm()
        {
            InitializeComponent();
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            try
            {
                this.loginManager.ServerIP = txtServer.Text;
                int uid = this.loginManager.Login(txtUser.Text, txtPwd.Text);
                ///this.loginManager.WriteHosts();

                if (uid == -1)
                {
                    MessageBox.Show("未找到该用户");
                    return;
                }

                string base64 = loginManager.GetLoginBase64(uid);
                ProcessStartInfo info = new ProcessStartInfo(@"C:\Users\Administrator\Desktop\地下城与勇士\DNF.exe", base64);
                info.UseShellExecute = false;
                info.WorkingDirectory = Path.GetDirectoryName(info.FileName);
                Process.Start(info);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

        }

        private void btnReg_Click(object sender, EventArgs e)
        {
            try
            {
                this.loginManager.ServerIP = txtServer.Text;
                bool suc = this.loginManager.Reg(txtUser.Text, txtPwd.Text);

                if (!suc)
                {
                    MessageBox.Show("该用户已存在");
                    return;
                }

                MessageBox.Show("注册成功");

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
    }
}