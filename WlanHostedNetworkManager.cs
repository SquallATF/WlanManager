using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace WlanManager
{
    class WlanHostedNetworkManager : IDisposable
    {
        private bool disposed = false;
        IntPtr hClientHandle;

        bool _isEnabled = false;
        public bool IsEnabled
        {
            get { return _isEnabled; }
        }

        string _ssid;
        public string SSID
        {
            get { return _ssid; }
        }

        uint _maxNumberOfPeers;
        public uint MaxNumberOfPeers
        {
            get { return _maxNumberOfPeers; }
        }

        string _authentication;
        public string Authentication
        {
            get { return _authentication; }
        }

        string _encryption;
        public string Encryption
        {
            get { return _encryption; }
        }

        bool _isStarted;
        public bool IsStarted
        {
            get { return _isStarted; }
        }

        string _bssid;
        public string BSSID
        {
            get { return _bssid; }
        }

        uint _channelFrequency;
        public uint ChannelFrequency
        {
            get { return _channelFrequency; }
        }

        public string Password
        {
            get
            {
                string key = null;
                uint keylen;
                IntPtr keydata;
                bool isPassPhrase;
                bool persistent;
                NativeMethods.WLAN_HOSTED_NETWORK_REASON failReason;
                uint err = NativeMethods.WlanHostedNetworkQuerySecondaryKey(
                    hClientHandle,
                    out keylen,
                    out keydata,
                    out isPassPhrase,
                    out persistent,
                    out failReason,
                    IntPtr.Zero);
                if (err == NativeMethods.ERROR_SUCCESS)
                {
                    if (keydata != IntPtr.Zero && keylen > 0)
                    {
                        key = Marshal.PtrToStringAnsi(keydata);
                    }
                }
                if (keydata != IntPtr.Zero)
                {
                    NativeMethods.WlanFreeMemory(keydata);
                }
                return key;
            }
        }

        public WlanHostedNetworkManager()
        {
            Refresh();
        }

        private void WlOpenHandle(ref IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                uint dwNegotiatedVersion;
                uint err = NativeMethods.WlanOpenHandle(2, IntPtr.Zero, out dwNegotiatedVersion, out handle);
                if (err != NativeMethods.ERROR_SUCCESS)
                {
                    throw new Win32Exception((int)err);
                }
            }
        }

        public void Refresh()
        {
            _isEnabled = false;
            _ssid = string.Empty;
            _maxNumberOfPeers = 0;
            _authentication = string.Empty;
            _encryption = string.Empty;
            _isStarted = false;
            _bssid = string.Empty;
            _channelFrequency = 0;

            WlOpenHandle(ref hClientHandle);
            uint dwDataSize;
            IntPtr pEnabled = IntPtr.Zero;
            IntPtr pConnectionSettings = IntPtr.Zero;
            IntPtr pSecuritySettings = IntPtr.Zero;
            IntPtr pWlanHostedNetworkStatus = IntPtr.Zero;
            bool haveConnectionSettings = true;
            bool haveSecuritySettings = false;
            NativeMethods.WLAN_OPCODE_VALUE_TYPE wlanOpcodeValueType;
            uint err = NativeMethods.WlanHostedNetworkQueryProperty(
                hClientHandle,
                NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_enable,
                out dwDataSize,
                out pEnabled,
                out wlanOpcodeValueType,
                IntPtr.Zero);
            if (err == NativeMethods.ERROR_SUCCESS)
            {
                int ret = Marshal.ReadInt32(pEnabled);
                _isEnabled = ret != 0;
            }

            if (dwDataSize >= 4)
            {
                err = NativeMethods.WlanHostedNetworkQueryProperty(
                    hClientHandle,
                    NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_connection_settings,
                    out dwDataSize,
                    out pConnectionSettings,
                    out wlanOpcodeValueType,
                    IntPtr.Zero);
                if (err == NativeMethods.ERROR_BAD_CONFIGURATION)
                {
                    haveConnectionSettings = false;
                    err = NativeMethods.ERROR_SUCCESS;
                }
                if (err == NativeMethods.ERROR_SUCCESS)
                {
                    if (haveConnectionSettings)
                    {
                        if (pConnectionSettings != IntPtr.Zero && dwDataSize >= 40)
                        {
                            dwDataSize = 0;

                            err = NativeMethods.WlanHostedNetworkQueryProperty(
                                hClientHandle,
                                NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_security_settings,
                                out dwDataSize,
                                out pSecuritySettings,
                                out wlanOpcodeValueType,
                                IntPtr.Zero);
                            if (err == NativeMethods.ERROR_SUCCESS)
                            {
                                if (pSecuritySettings != IntPtr.Zero && dwDataSize >= 8)
                                {
                                    haveSecuritySettings = true;
                                }
                            }
                        }
                    }

                    if (!haveConnectionSettings || haveSecuritySettings)
                    {
                        err = NativeMethods.WlanHostedNetworkQueryStatus(
                            hClientHandle,
                            out pWlanHostedNetworkStatus,
                            IntPtr.Zero);
                        if (err == NativeMethods.ERROR_SUCCESS)
                        {
                            if (pWlanHostedNetworkStatus != IntPtr.Zero)
                            {
                                if (haveConnectionSettings)
                                {
                                    var connectionSettings = (NativeMethods.WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS)
                                        Marshal.PtrToStructure(pConnectionSettings,
                                        typeof(NativeMethods.WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS));
                                    _ssid = connectionSettings.hostedNetworkSSID.ucSSID;
                                    _maxNumberOfPeers = connectionSettings.dwMaxNumberOfPeers;

                                    var securitySettings = (NativeMethods.WLAN_HOSTED_NETWORK_SECURITY_SETTINGS)
                                        Marshal.PtrToStructure(pSecuritySettings,
                                        typeof(NativeMethods.WLAN_HOSTED_NETWORK_SECURITY_SETTINGS));
                                    _authentication = GenAuthenticationStr(securitySettings.dot11AuthAlgo);
                                    _encryption = GenEncryptionStr(securitySettings.dot11CipherAlgo);
                                }

                                var status = new NativeMethods.WLAN_HOSTED_NETWORK_STATUS(pWlanHostedNetworkStatus);
                                _isStarted = status.HostedNetworkState == NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_active;
                                _bssid = string.Join(":", status.wlanHostedNetworkBSSID.Select(b => b.ToString("X2")).ToArray());
                                _channelFrequency = status.ulChannelFrequency;
                            }
                        }
                    }
                }
            }

            if (pEnabled != IntPtr.Zero)
            {
                NativeMethods.WlanFreeMemory(pEnabled);
            }

            if (pConnectionSettings != IntPtr.Zero)
            {
                NativeMethods.WlanFreeMemory(pConnectionSettings);
            }

            if (pSecuritySettings != IntPtr.Zero)
            {
                NativeMethods.WlanFreeMemory(pSecuritySettings);
            }

            if (pWlanHostedNetworkStatus != IntPtr.Zero)
            {
                NativeMethods.WlanFreeMemory(pWlanHostedNetworkStatus);
            }
        }

        ~WlanHostedNetworkManager()
        {
            Dispose(false);
        }

        public bool Start()
        {
            WlOpenHandle(ref hClientHandle);
            NativeMethods.WLAN_HOSTED_NETWORK_REASON failedReson;
            uint err = NativeMethods.WlanHostedNetworkForceStart(hClientHandle, out failedReson, IntPtr.Zero);
            bool ret = err == NativeMethods.ERROR_SUCCESS;
            if (ret)
            {
                Refresh();
                _isStarted = true;
            }
            return ret;
        }

        public bool Stop()
        {
            WlOpenHandle(ref hClientHandle);
            NativeMethods.WLAN_HOSTED_NETWORK_REASON failedReson;
            uint err = NativeMethods.WlanHostedNetworkForceStop(hClientHandle, out failedReson, IntPtr.Zero);
            bool ret = err == NativeMethods.ERROR_SUCCESS;
            if (ret)
            {
                Refresh();
                _isStarted = false;
            }
            return ret;
        }

        public void Config(bool enable, string ssid, string password)
        {
            WlOpenHandle(ref hClientHandle);
            uint dwDataSize = (uint)Marshal.SizeOf(typeof(int));
            IntPtr pEnabled = Marshal.AllocHGlobal((int)dwDataSize);
            Marshal.WriteInt32(pEnabled, 0, enable ? 1 : 0);
            //pEnabled 
            NativeMethods.WLAN_HOSTED_NETWORK_REASON failedReson;
            uint err = NativeMethods.WlanHostedNetworkSetProperty(
                hClientHandle,
                NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_enable,
                dwDataSize,
                pEnabled,
                out failedReson,
                IntPtr.Zero);
            if (err == NativeMethods.ERROR_SUCCESS)
            { }

            dwDataSize = (uint)Marshal.SizeOf(typeof(NativeMethods.WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS));
            IntPtr pConnectionSettings = Marshal.AllocHGlobal((int)dwDataSize);
            NativeMethods.WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS connectionSetting;
            connectionSetting.dwMaxNumberOfPeers = 100;
            connectionSetting.hostedNetworkSSID.ucSSID = ssid;
            connectionSetting.hostedNetworkSSID.uSSIDLength = (uint)ssid.Length;
            Marshal.StructureToPtr(connectionSetting, pConnectionSettings, false);
            err = NativeMethods.WlanHostedNetworkSetProperty(
                hClientHandle,
                NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_connection_settings,
                dwDataSize,
                pConnectionSettings,
                out failedReson,
                IntPtr.Zero);
            if (err == NativeMethods.ERROR_SUCCESS)
            { }

            password += '\0';
            err = NativeMethods.WlanHostedNetworkSetSecondaryKey(
                hClientHandle,
                (uint)password.Length,
                password,
                true,
                true,
                out failedReson,
                IntPtr.Zero);
            if (err == NativeMethods.ERROR_SUCCESS)
            { }
            if (pEnabled != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pEnabled);
            }
            if (pConnectionSettings != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pConnectionSettings);
            }
            Refresh();
        }

        string GenAuthenticationStr(NativeMethods.DOT11_AUTH_ALGORITHM dot11AuthAlgorithm)
        {
            switch (dot11AuthAlgorithm)
            {
                case NativeMethods.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_OPEN:
                    return "Open";
                case NativeMethods.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_SHARED_KEY:
                    return "Shared Key";
                case NativeMethods.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA:
                    return "WPA";
                case NativeMethods.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA_PSK:
                    return "WPA-PSK";
                case NativeMethods.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA_NONE:
                    return "WPA-None";
                case NativeMethods.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_RSNA:
                    return "WPA2";
                case NativeMethods.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_RSNA_PSK:
                    return "WPA2-PSK";
                default:
                    return "Unknown Authentication";
            }
        }

        string GenEncryptionStr(NativeMethods.DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm)
        {
            switch (dot11CipherAlgorithm)
            {
                case NativeMethods.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_NONE:
                    return "Unencrypted";
                case NativeMethods.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP40:
                    return "WEP (40-bit key)";
                case NativeMethods.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_TKIP:
                    return "TKIP";
                case NativeMethods.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_CCMP:
                    return "AES";
                case NativeMethods.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP104:
                    return "WEP (104-bit key)";
                case NativeMethods.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WPA_USE_GROUP:
                    return "Use Group Key";
                case NativeMethods.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP:
                    return "WEP";
                default:
                    return "Unknown Encryption";
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (hClientHandle != IntPtr.Zero)
                {
                    NativeMethods.WlanCloseHandle(hClientHandle, IntPtr.Zero);
                    hClientHandle = IntPtr.Zero;
                }
            }
            disposed = true;
        }
    }
}
