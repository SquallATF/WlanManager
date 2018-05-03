using System;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Threading.Tasks;

namespace WlanManager
{
    [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust", Unrestricted = false)]
    class WlanHostedNetworkManager : IDisposable
    {
        private bool _disposed;
        private readonly WlanHandle _hClientHandle;
        private Guid _hostedNetworkInterfaceGuid;
        private static readonly object _lock = new object();

        private readonly ICSManager _icsManager;

        private bool _isEnabled;
        public bool IsEnabled => _isEnabled;

        private string _ssid;
        public string SSID => _ssid;

        uint _maxNumberOfPeers;
        public uint MaxNumberOfPeers => _maxNumberOfPeers;

        string _authentication;
        public string Authentication => _authentication;

        string _encryption;
        public string Encryption => _encryption;

        bool _isStarted;
        public bool IsStarted => _isStarted;

        string _bssid;
        public string BSSID => _bssid;

        uint _channelFrequency;
        public uint ChannelFrequency => _channelFrequency;

        public string Password
        {
            get
            {
                string key = null;
                uint err = NativeMethods.WlanHostedNetworkQuerySecondaryKey(
                    _hClientHandle,
                    out var keylen,
                    out var keydata,
                    out _,
                    out _,
                    out _,
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

        public event EventHandler EnableStateChanged;
        public event EventHandler StartStateChanged;

        public WlanHostedNetworkManager()
        {
            uint err = NativeMethods.WlanOpenHandle(NativeMethods.WLAN_API_VERSION_2_0, IntPtr.Zero, out _, out WlanHandle handle);
            if (err != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception((int)err);
            }

            _hClientHandle = handle;

            err = NativeMethods.WlanRegisterNotification(_hClientHandle,
                NativeMethods.WLAN_NOTIFICATION_SOURCE_HNWK, true, OnNotification, IntPtr.Zero,
                IntPtr.Zero, out _);
            if (err != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception((int)err);
            }

            Refresh();
            _icsManager = new ICSManager();
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

            IntPtr pConnectionSettings = IntPtr.Zero;
            IntPtr pSecuritySettings = IntPtr.Zero;
            IntPtr pWlanHostedNetworkStatus = IntPtr.Zero;
            uint err = NativeMethods.WlanHostedNetworkQueryProperty(
                _hClientHandle,
                NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_enable,
                out _,
                out var pEnabled,
                out _);
            if (err == NativeMethods.ERROR_SUCCESS)
            {
                int ret = Marshal.ReadInt32(pEnabled);
                _isEnabled = ret != 0;

                err = NativeMethods.WlanHostedNetworkQueryProperty(
                    _hClientHandle,
                    NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_connection_settings,
                    out _,
                    out pConnectionSettings,
                    out _);
                if (err == NativeMethods.ERROR_SUCCESS)
                {
                    var connectionSettings = Marshal.PtrToStructure<NativeMethods.WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>(pConnectionSettings);
                    _ssid = connectionSettings.hostedNetworkSSID.ucSSID;
                    _maxNumberOfPeers = connectionSettings.dwMaxNumberOfPeers;
                }

                err = NativeMethods.WlanHostedNetworkQueryProperty(
                    _hClientHandle,
                    NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_security_settings,
                    out _,
                    out pSecuritySettings,
                    out _);
                if (err == NativeMethods.ERROR_SUCCESS)
                {
                    var securitySettings = Marshal.PtrToStructure<NativeMethods.WLAN_HOSTED_NETWORK_SECURITY_SETTINGS>(pSecuritySettings);
                    _authentication = GenAuthenticationStr(securitySettings.dot11AuthAlgo);
                    _encryption = GenEncryptionStr(securitySettings.dot11CipherAlgo);
                }
                err = NativeMethods.WlanHostedNetworkQueryStatus(
                    _hClientHandle,
                    out pWlanHostedNetworkStatus);
                if (err == NativeMethods.ERROR_SUCCESS)
                {
                    var status = new NativeMethods.WLAN_HOSTED_NETWORK_STATUS(pWlanHostedNetworkStatus);
                    _isStarted = status.HostedNetworkState == NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_active;
                    _hostedNetworkInterfaceGuid = status.IPDeviceID;
                    _bssid = string.Join(":", status.wlanHostedNetworkBSSID.Select(b => b.ToString("X2")).ToArray());
                    _channelFrequency = status.ulChannelFrequency;

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

        public Task<bool> Start()
        {
            lock (_lock)
            {
                uint err;
                if (_isStarted)
                {
                    err = NativeMethods.WlanHostedNetworkForceStop(_hClientHandle, out _);
                    if (err != NativeMethods.ERROR_SUCCESS)
                    {
                        throw new Win32Exception((int)err);
                    }

                }
                err = NativeMethods.WlanHostedNetworkStartUsing(_hClientHandle, out _);
                // uint err = NativeMethods.WlanHostedNetworkForceStart(_hClientHandle, out _);
                bool ret = err == NativeMethods.ERROR_SUCCESS;
                if (ret)
                {
                    Refresh();
                    _isStarted = true;

                    if (_icsManager == null || !_icsManager.IsServiceStatusValid)
                    {
                        throw new Exception("ICSManager is invalid or ICS service is in pending state");
                    }
                    else
                    {
                        var privateGuid = _hostedNetworkInterfaceGuid;
                        var publicGuid = GetPreferredPublicGuid(privateGuid);

                        _icsManager.EnableSharing(publicGuid, privateGuid);
                    }

                }
                return Task.FromResult(ret);
            }
        }

        public Task<bool> Stop(bool force = true)
        {
            lock (_lock)
            {
                if (!_isStarted)
                {
                    return Task.FromResult(false);
                }

                uint err;
                if (force)
                {
                    err = NativeMethods.WlanHostedNetworkForceStop(_hClientHandle, out _);

                }
                else
                {
                    err = NativeMethods.WlanHostedNetworkStopUsing(_hClientHandle, out _);
                    if (err != NativeMethods.ERROR_SUCCESS)
                    {
                        err = NativeMethods.WlanHostedNetworkForceStop(_hClientHandle, out _);
                    }
                }
                bool ret = err == NativeMethods.ERROR_SUCCESS;
                if (ret)
                {
                    Refresh();
                    _isStarted = false;
                }
                return Task.FromResult(ret);
            }
        }

        public void Config(bool enable, string ssid, string password)
        {
            uint dwDataSize = (uint)Marshal.SizeOf(typeof(int));
            IntPtr pEnabled = Marshal.AllocHGlobal((int)dwDataSize);
            Marshal.WriteInt32(pEnabled, 0, enable ? 1 : 0);
            //pEnabled 
            uint err = NativeMethods.WlanHostedNetworkSetProperty(
                _hClientHandle,
                NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_enable,
                dwDataSize,
                pEnabled,
                out _);
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
                _hClientHandle,
                NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_connection_settings,
                dwDataSize,
                pConnectionSettings,
                out _);
            if (err == NativeMethods.ERROR_SUCCESS)
            { }

            password += '\0';
            err = NativeMethods.WlanHostedNetworkSetSecondaryKey(
                _hClientHandle,
                (uint)password.Length,
                password,
                true,
                true,
                out _);
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

        private string GenAuthenticationStr(NativeMethods.DOT11_AUTH_ALGORITHM dot11AuthAlgorithm)
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

        private string GenEncryptionStr(NativeMethods.DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm)
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

        private void OnNotification(NativeMethods.WLAN_NOTIFICATION_DATA data, IntPtr context)
        {
            if (data.NotificationSource == NativeMethods.WLAN_NOTIFICATION_SOURCE_HNWK)
            {
                switch (data.NotificationCode)
                {
                    case NativeMethods.WLAN_HOSTED_NETWORK_NOTIFICATION_CODE.wlan_hosted_network_state_change:
                        var stateChange =
                            Marshal.PtrToStructure<NativeMethods.WLAN_HOSTED_NETWORK_STATE_CHANGE>(data.pData);

                        switch (stateChange.NewState)
                        {
                            case NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_active:
                                OnHostedNetworkStarted();
                                break;
                            case NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_idle:
                                if (stateChange.OldState == NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_active)
                                {
                                    OnHostedNetworkStopped();
                                }
                                else
                                {
                                    OnHostedNetworkEnabled();
                                }
                                break;
                            case NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_unavailable:
                                if (stateChange.OldState == NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_active)
                                {
                                    OnHostedNetworkStopped();
                                }
                                OnHostedNetworkDisabled();
                                break;
                        }

                        break;
                    case NativeMethods.WLAN_HOSTED_NETWORK_NOTIFICATION_CODE.wlan_hosted_network_peer_state_change:
                        var peerStateChange =
                            Marshal.PtrToStructure<NativeMethods.WLAN_HOSTED_NETWORK_DATA_PEER_STATE_CHANGE>(
                                data.pData);
                        if (peerStateChange.NewState.PeerAuthState == NativeMethods.WLAN_HOSTED_NETWORK_PEER_AUTH_STATE.wlan_hosted_network_peer_state_authenticated)
                        {
                            OnDeviceConnected(peerStateChange.NewState);
                        }
                        if (peerStateChange.NewState.PeerAuthState == NativeMethods.WLAN_HOSTED_NETWORK_PEER_AUTH_STATE.wlan_hosted_network_peer_state_invalid)
                        {
                            OnDeviceDisconnected(peerStateChange.NewState.PeerMacAddress);
                        }
                        break;
                }
            }

        }

        private void OnHostedNetworkEnabled()
        {
            _isEnabled = true;
            EnableStateChanged?.Invoke(this, EventArgs.Empty);
        }

        private void OnHostedNetworkDisabled()
        {
            _isEnabled = false;
            _isStarted = false;
            EnableStateChanged?.Invoke(this, EventArgs.Empty);

        }
        private void OnHostedNetworkStarted()
        {
            _isStarted = true;
            StartStateChanged?.Invoke(this, EventArgs.Empty);
        }

        private void OnHostedNetworkStopped()
        {
            _isStarted = false;
            StartStateChanged?.Invoke(this, EventArgs.Empty);

        }

        private void OnDeviceConnected(NativeMethods.WLAN_HOSTED_NETWORK_PEER_STATE newState)
        {

        }

        private void OnDeviceDisconnected(byte[] newStatePeerMacAddress)
        {


        }

        private static Func<SocketAddress, byte[]> testFunc = CreateGetXXX();
        private static Func<IPAddress, SocketAddress> createSa = CreateCreateXXX();

        private static Guid GetPreferredPublicGuid(Guid privateGuid)
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            //var nic = nics.FirstOrDefault(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet
            //                                   && n.OperationalStatus == OperationalStatus.Up) ??
            //          nics.FirstOrDefault(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211
            //                                   && n.OperationalStatus == OperationalStatus.Up
            //                                   && new Guid(n.Id) != privateGuid);
            var hostInfo = Dns.GetHostEntry("www.baidu.com");
            var ipAddr = hostInfo.AddressList[0];
            var sa = createSa(ipAddr);
            var sabuffer = testFunc(sa);

            NativeMethods.GetBestInterfaceEx(sabuffer, out uint bestIfIndex);

            //NativeMethods.GetBestInterface()
            var nic = nics.FirstOrDefault(n =>
            {
                var ipProps = n.GetIPProperties();
                var match = false;
                if (ipAddr.AddressFamily == AddressFamily.InterNetwork)
                {
                    match = ipProps.GetIPv4Properties().Index == bestIfIndex;
                }

                if (ipAddr.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    match = ipProps.GetIPv6Properties().Index == bestIfIndex;
                }
                return n.OperationalStatus == OperationalStatus.Up && match;
            });

            if (nic == null)
            {
                throw new ApplicationException("No preferred public network is available.");
            }

            return new Guid(nic.Id);
        }

        static Func<SocketAddress, byte[]> CreateGetXXX()
        {
            DynamicMethod dm = new DynamicMethod("GetBuffer", typeof(byte[]), new[] { typeof(SocketAddress) }, typeof(SocketAddress));
            var field = typeof(SocketAddress).GetField("m_Buffer", BindingFlags.Instance | BindingFlags.NonPublic);
            if (field == null)
            {
                throw new Exception("Api Broken");
            }
            var il = dm.GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldfld, field);
            il.Emit(OpCodes.Ret);
            return (Func<SocketAddress, byte[]>)dm.CreateDelegate(typeof(Func<SocketAddress, byte[]>));
        }

        static Func<IPAddress, SocketAddress> CreateCreateXXX()
        {
            DynamicMethod dm = new DynamicMethod("CreateSA", typeof(SocketAddress), new[] { typeof(IPAddress) }, typeof(SocketAddress));
            var ctor = typeof(SocketAddress).GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new[] { typeof(IPAddress) }, null);
            if (ctor == null)
            {
                throw new Exception("Api Broken");
            }
            var il = dm.GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Newobj, ctor);
            il.Emit(OpCodes.Ret);
            return (Func<IPAddress, SocketAddress>)dm.CreateDelegate(typeof(Func<IPAddress, SocketAddress>));
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;
            if (disposing)
            {
                _icsManager?.Dispose();

            }
            if (_hClientHandle != null && !_hClientHandle.IsInvalid)
            {
                _hClientHandle.Dispose();
            }
            _disposed = true;
        }
    }
}
