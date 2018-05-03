using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace WlanManager
{
    public partial class MainForm : Form
    {
        // ReSharper disable ArrangeTypeMemberModifiers
        // ReSharper disable UnusedMember.Local
        // ReSharper disable InconsistentNaming
        const int WM_DEVICECHANGE = 0x0219;
        const int DBT_CONFIGCHANGECANCELED = 0x0019;
        const int DBT_CONFIGCHANGED = 0x0018;
        const int DBT_CUSTOMEVENT = 0x8006;
        const int DBT_DEVICEARRIVAL = 0x8000;
        const int DBT_DEVICEQUERYREMOVE = 0x8001;
        const int DBT_DEVICEQUERYREMOVEFAILED = 0x8002;
        const int DBT_DEVICEREMOVECOMPLETE = 0x8004;
        const int DBT_DEVICEREMOVEPENDING = 0x8003;
        const int DBT_DEVICETYPESPECIFIC = 0x8005;
        const int DBT_DEVNODES_CHANGED = 0x0007;
        const int DBT_QUERYCHANGECONFIG = 0x0017;
        const int DBT_USERDEFINED = 0xFFFF;
        const uint DBT_DEVTYP_DEVICEINTERFACE = 0x00000005;
        const uint DEVICE_NOTIFY_WINDOW_HANDLE = 0x00000000;
        const uint DEVICE_NOTIFY_SERVICE_HANDLE = 0x00000001;
        const uint DEVICE_NOTIFY_ALL_INTERFACE_CLASSES = 0x00000004;
        static readonly Guid GUID_DEVINTERFACE_USB_DEVICE = new Guid("{a5dcbf10-6530-11d2-901f-00c04fb951ed}");
        // ReSharper restore InconsistentNaming
        // ReSharper restore UnusedMember.Local
        // ReSharper restore ArrangeTypeMemberModifiers

        private readonly WlanHostedNetworkManager _wlanHostedNetworkManager = new WlanHostedNetworkManager();
        private IntPtr _hDevNotify = IntPtr.Zero;

        public MainForm()
        {
            InitializeComponent();
            _wlanHostedNetworkManager.EnableStateChanged += _wlanHostedNetworkManager_EnableStateChanged;
            _wlanHostedNetworkManager.StartStateChanged += _wlanHostedNetworkManager_StartStateChanged;
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
            try
            {
                var dbh = new NativeMethods.DEV_BROADCAST_DEVICEINTERFACE();
                dbh.dbch_size = (uint)Marshal.SizeOf(dbh);
                dbh.dbch_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
                dbh.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;
                IntPtr pFilter = Marshal.AllocHGlobal(Marshal.SizeOf(dbh));
                Marshal.StructureToPtr(dbh, pFilter, false);
                _hDevNotify = NativeMethods.RegisterDeviceNotification(Handle, pFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
                if (_hDevNotify == IntPtr.Zero)
                {
                    System.Diagnostics.Debug.WriteLine("false");
                }
                Marshal.FreeHGlobal(pFilter);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
            }
        }

        private void LoadInfo()
        {
            modeLabel.Text = _wlanHostedNetworkManager.IsEnabled ? "已启用" : "已禁用";
            stateGroupBox.Enabled = _wlanHostedNetworkManager.IsEnabled;
            ssidLabel.Text = _wlanHostedNetworkManager.SSID;
            maxLabel.Text = _wlanHostedNetworkManager.MaxNumberOfPeers.ToString();
            authLabel.Text = _wlanHostedNetworkManager.Authentication;
            encLabel.Text = _wlanHostedNetworkManager.Encryption;
            if (_wlanHostedNetworkManager.IsEnabled)
            {
                statusLabel.Text = _wlanHostedNetworkManager.IsStarted ? "已启动" : "已停止";
                bssidLabel.Text = _wlanHostedNetworkManager.BSSID;
                chLabel.Text = _wlanHostedNetworkManager.ChannelFrequency.ToString();
                if (_wlanHostedNetworkManager.IsStarted)
                {
                    button1.Enabled = false;
                    button2.Enabled = true;
                    button3.Enabled = false;
                }
                else
                {
                    button1.Enabled = true;
                    button2.Enabled = false;
                    button3.Enabled = true;
                }
            }
            else
            {
                button1.Enabled = false;
                button2.Enabled = false;
                button3.Enabled = true;
            }
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_DEVICECHANGE)
            {
                int dcEvent = m.WParam.ToInt32();
                switch (dcEvent)
                {
                    case DBT_DEVICEARRIVAL:
                        System.Diagnostics.Debug.WriteLine("DBT_DEVICEARRIVAL");
                        _wlanHostedNetworkManager.Refresh();
                        LoadInfo();
                        try
                        {
                            NativeMethods.DEV_BROADCAST_HDR hdr;
                            hdr = (NativeMethods.DEV_BROADCAST_HDR)Marshal.PtrToStructure(m.LParam, typeof(NativeMethods.DEV_BROADCAST_HDR));
                            if (hdr.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
                            {
                                var hdr1 = (NativeMethods.DEV_BROADCAST_DEVICEINTERFACE)Marshal.PtrToStructure(m.LParam, typeof(NativeMethods.DEV_BROADCAST_DEVICEINTERFACE));
                                System.Diagnostics.Debug.WriteLine(hdr1.dbcc_name);
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine(ex.Message);
                        }
                        break;
                    case DBT_DEVICEREMOVECOMPLETE:
                        System.Diagnostics.Debug.WriteLine("DBT_DEVICEREMOVECOMPLETE");
                        _wlanHostedNetworkManager.Refresh();
                        LoadInfo();
                        break;
                }
            }

            base.WndProc(ref m);
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (_hDevNotify != IntPtr.Zero)
            {
                NativeMethods.UnregisterDeviceNotification(_hDevNotify);
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
