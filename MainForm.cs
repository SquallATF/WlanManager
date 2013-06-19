using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace WlanManager
{
    public partial class MainForm : Form
    {
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

        WlanHostedNetworkManager wlanHostedNetworkManager = new WlanHostedNetworkManager();
        IntPtr hDevNotify = IntPtr.Zero;

        public MainForm()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (wlanHostedNetworkManager.Start())
            {
                button3.Enabled = false;
                LoadInfo();
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (wlanHostedNetworkManager.Stop())
            {
                LoadInfo();
                button3.Enabled = true;
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            LoadInfo();
            if (wlanHostedNetworkManager.IsStarted)
            {
                button3.Enabled = false;
            }
            try
            {
                var dbh = new NativeMethods.DEV_BROADCAST_DEVICEINTERFACE();
                dbh.dbch_size = (uint)Marshal.SizeOf(dbh);
                dbh.dbch_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
                dbh.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;
                IntPtr pFilter = Marshal.AllocHGlobal(Marshal.SizeOf(dbh));
                Marshal.StructureToPtr(dbh, pFilter, false);
                hDevNotify = NativeMethods.RegisterDeviceNotification(Handle, pFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
                if (hDevNotify == IntPtr.Zero)
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
            modeLabel.Text = wlanHostedNetworkManager.IsEnabled ? "已启用" : "已禁用";
            stateGroupBox.Enabled = wlanHostedNetworkManager.IsEnabled;
            ssidLabel.Text = wlanHostedNetworkManager.SSID;
            maxLabel.Text = wlanHostedNetworkManager.MaxNumberOfPeers.ToString();
            authLabel.Text = wlanHostedNetworkManager.Authentication;
            encLabel.Text = wlanHostedNetworkManager.Encryption;
            if (wlanHostedNetworkManager.IsEnabled)
            {
                statusLabel.Text = wlanHostedNetworkManager.IsStarted ? "已启动" : "已停止";
                bssidLabel.Text = wlanHostedNetworkManager.BSSID;
                chLabel.Text = wlanHostedNetworkManager.ChannelFrequency.ToString();
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
                        wlanHostedNetworkManager.Refresh();
                        LoadInfo();
                        try
                        {
                            NativeMethods.DEV_BROADCAST_HDR hdr;
                            hdr = (NativeMethods.DEV_BROADCAST_HDR)Marshal.PtrToStructure(m.LParam, typeof(NativeMethods.DEV_BROADCAST_HDR));
                            if (hdr.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
                            {
                                var hdr1 = (NativeMethods.DEV_BROADCAST_DEVICEINTERFACE)Marshal.PtrToStructure(m.LParam, typeof(NativeMethods.DEV_BROADCAST_DEVICEINTERFACE));
                                System.Diagnostics.Debug.WriteLine((string)hdr1.dbcc_name);
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine(ex.Message);
                        }
                        break;
                    case DBT_DEVICEREMOVECOMPLETE:
                        System.Diagnostics.Debug.WriteLine("DBT_DEVICEREMOVECOMPLETE");
                        wlanHostedNetworkManager.Refresh();
                        LoadInfo();
                        break;
                }
            }

            base.WndProc(ref m);
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (hDevNotify != IntPtr.Zero)
            {
                NativeMethods.UnregisterDeviceNotification(hDevNotify);
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            ConfigForm configForm = new ConfigForm(wlanHostedNetworkManager);
            if (configForm.ShowDialog() == DialogResult.OK)
            {
                LoadInfo();
            }
        }
    }
}
