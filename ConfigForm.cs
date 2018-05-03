using System;
using System.Windows.Forms;

namespace WlanManager
{
    partial class ConfigForm : Form
    {
        private readonly WlanHostedNetworkManager _wlanHostedNetworkManager;

        public ConfigForm(WlanHostedNetworkManager wlanHostedNetworkManager)
        {
            _wlanHostedNetworkManager = wlanHostedNetworkManager;
            InitializeComponent();
            textBox1.Text = wlanHostedNetworkManager.SSID;
            textBox2.Text = wlanHostedNetworkManager.Password;
            checkBox2.Checked = wlanHostedNetworkManager.IsEnabled;
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            textBox2.UseSystemPasswordChar = !checkBox1.Checked;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            _wlanHostedNetworkManager.Config(checkBox2.Checked, textBox1.Text, textBox2.Text);
            //wlanHostedNetworkManager.SSID = textBox1.Text;
            //wlanHostedNetworkManager.Password = textBox2.Text;
            //wlanHostedNetworkManager.IsEnabled = checkBox2.Checked;
        }
    }
}
