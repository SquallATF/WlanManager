using System;
using System.Windows.Forms;

namespace WlanManager
{
    public partial class MainForm : Form
    {
        private readonly WlanHostedNetworkManager _wlanHostedNetworkManager = new WlanHostedNetworkManager();

        public MainForm()
        {
            InitializeComponent();
            _wlanHostedNetworkManager.EnableStateChanged += _wlanHostedNetworkManager_EnableStateChanged;
            _wlanHostedNetworkManager.StartStateChanged += _wlanHostedNetworkManager_StartStateChanged;
            _wlanHostedNetworkManager.DeviceConnected += _wlanHostedNetworkManager_DeviceConnected;
            _wlanHostedNetworkManager.DeviceDisconnected += _wlanHostedNetworkManager_DeviceConnected;
        }

        private void _wlanHostedNetworkManager_DeviceConnected(object sender, EventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(UpdateNumberOfPeers));
            }
            else
            {
                UpdateNumberOfPeers();
            }
        }

        private void _wlanHostedNetworkManager_EnableStateChanged(object sender, EventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(LoadInfo));
            }
            else
            {
                LoadInfo();
            }
        }

        private void _wlanHostedNetworkManager_StartStateChanged(object sender, EventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(LoadInfo));
            }
            else
            {
                LoadInfo();
            }
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            button1.Enabled = false;
            if (!await _wlanHostedNetworkManager.Start())
            {
                button1.Enabled = true;
            }
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            button2.Enabled = false;
            if (!await _wlanHostedNetworkManager.Stop())
            {
                button2.Enabled = true;
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            LoadInfo();
        }

        private void UpdateNumberOfPeers()
        {
            numLabel.Text = _wlanHostedNetworkManager.NumberOfPeers.ToString();
        }

        private void LoadInfo()
        {
            modeLabel.Text = _wlanHostedNetworkManager.IsEnabled ? "已启用" : "已禁用";
            stateGroupBox.Enabled = _wlanHostedNetworkManager.IsEnabled;
            if (_wlanHostedNetworkManager.IsEnabled)
            {
                ssidLabel.Text = _wlanHostedNetworkManager.SSID;
                maxLabel.Text = _wlanHostedNetworkManager.MaxNumberOfPeers.ToString();
                authLabel.Text = _wlanHostedNetworkManager.Authentication;
                encLabel.Text = _wlanHostedNetworkManager.Encryption;
                statusLabel.Text = _wlanHostedNetworkManager.IsStarted ? "已启动" : "已停止";
                if (_wlanHostedNetworkManager.IsStarted)
                {
                    bssidLabel.Text = _wlanHostedNetworkManager.BSSID;
                    chLabel.Text = _wlanHostedNetworkManager.ChannelFrequency.ToString();
                    numLabel.Text = _wlanHostedNetworkManager.NumberOfPeers.ToString();
                    button1.Enabled = false;
                    button2.Enabled = true;
                    button3.Enabled = false;
                }
                else
                {
                    bssidLabel.Text = string.Empty;
                    chLabel.Text = string.Empty;
                    numLabel.Text = string.Empty;
                    button1.Enabled = true;
                    button2.Enabled = false;
                    button3.Enabled = true;
                }
            }
            else
            {
                ssidLabel.Text = string.Empty;
                maxLabel.Text = string.Empty;
                authLabel.Text = string.Empty;
                encLabel.Text = string.Empty;
                button1.Enabled = false;
                button2.Enabled = false;
                button3.Enabled = true;
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            ConfigForm configForm = new ConfigForm(_wlanHostedNetworkManager);
            if (configForm.ShowDialog() == DialogResult.OK)
            {
                LoadInfo();
            }
        }
    }
}
