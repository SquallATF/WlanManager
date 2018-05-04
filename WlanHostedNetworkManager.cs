using System;
using System.ComponentModel;
using System.Linq;
using System.Linq.Expressions;
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
        private readonly object _lock = new object();

        private readonly ICSManager _icsManager;

        public bool IsEnabled { get; private set; }

        // ReSharper disable once InconsistentNaming
        public string SSID { get; private set; }

        public uint MaxNumberOfPeers { get; private set; }

        public string Authentication { get; private set; }

        public string Encryption { get; private set; }

        public bool IsStarted { get; private set; }

        // ReSharper disable once InconsistentNaming
        public string BSSID { get; private set; }

        public uint ChannelFrequency { get; private set; }

        public uint NumberOfPeers { get; private set; }

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
        public event EventHandler DeviceConnected;
        public event EventHandler DeviceDisconnected;

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

            Init();
            _icsManager = new ICSManager();
        }

        private void Init()
        {
            IsEnabled = false;
            SSID = string.Empty;
            MaxNumberOfPeers = 0;
            Authentication = string.Empty;
            Encryption = string.Empty;
            IsStarted = false;
            BSSID = string.Empty;
            ChannelFrequency = 0;

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
                IsEnabled = ret != 0;

                err = NativeMethods.WlanHostedNetworkQueryProperty(
                    _hClientHandle,
                    NativeMethods.WLAN_HOSTED_NETWORK_OPCODE.wlan_hosted_network_opcode_connection_settings,
                    out _,
                    out pConnectionSettings,
                    out _);
                if (err == NativeMethods.ERROR_SUCCESS)
                {
                    var connectionSettings = Marshal.PtrToStructure<NativeMethods.WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>(pConnectionSettings);
                    SSID = connectionSettings.hostedNetworkSSID.ucSSID;
                    MaxNumberOfPeers = connectionSettings.dwMaxNumberOfPeers;
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
                    Authentication = GenAuthenticationStr(securitySettings.dot11AuthAlgo);
                    Encryption = GenEncryptionStr(securitySettings.dot11CipherAlgo);
                }
                err = NativeMethods.WlanHostedNetworkQueryStatus(
                    _hClientHandle,
                    out pWlanHostedNetworkStatus);
                if (err == NativeMethods.ERROR_SUCCESS)
                {
                    var status = new NativeMethods.WLAN_HOSTED_NETWORK_STATUS(pWlanHostedNetworkStatus);
                    IsStarted = status.HostedNetworkState == NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_active;
                    if (status.HostedNetworkState !=
                        NativeMethods.WLAN_HOSTED_NETWORK_STATE.wlan_hosted_network_unavailable)
                    {
                        _hostedNetworkInterfaceGuid = status.IPDeviceID;
                        BSSID = string.Join(":", status.wlanHostedNetworkBSSID.Select(b => b.ToString("X2")).ToArray());
                        if (IsStarted)
                        {
                            ChannelFrequency = status.ulChannelFrequency;
                            NumberOfPeers = status.dwNumberOfPeers;
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

        public Task<bool> Start()
        {
            lock (_lock)
            {
                uint err;
                if (IsStarted)
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
                    IsStarted = true;

                    if (_icsManager == null || !_icsManager.IsServiceStatusValid)
                    {
                        throw new Exception("ICSManager is invalid or ICS service is in pending state");
                    }
                    else
                    {
                        var privateGuid = _hostedNetworkInterfaceGuid;
                        var publicGuid = GetPreferredPublicGuid();

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
                if (!IsStarted)
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
                    IsStarted = false;
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
            Init();
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
                            OnDeviceConnected();
                        }
                        if (peerStateChange.NewState.PeerAuthState == NativeMethods.WLAN_HOSTED_NETWORK_PEER_AUTH_STATE.wlan_hosted_network_peer_state_invalid)
                        {
                            OnDeviceDisconnected();
                        }
                        break;
                }
            }

        }

        private void OnHostedNetworkEnabled()
        {
            IsEnabled = true;
            Init();
            EnableStateChanged?.Invoke(this, EventArgs.Empty);
        }

        private void OnHostedNetworkDisabled()
        {
            IsEnabled = false;
            IsStarted = false;
            EnableStateChanged?.Invoke(this, EventArgs.Empty);

        }
        private void OnHostedNetworkStarted()
        {
            IsStarted = true;
            StartStateChanged?.Invoke(this, EventArgs.Empty);
        }

        private void OnHostedNetworkStopped()
        {
            IsStarted = false;
            StartStateChanged?.Invoke(this, EventArgs.Empty);

        }

        private void OnDeviceConnected()
        {
            NumberOfPeers++;
            DeviceConnected?.Invoke(this, EventArgs.Empty);
        }

        private void OnDeviceDisconnected()
        {
            NumberOfPeers--;
            DeviceDisconnected?.Invoke(this, EventArgs.Empty);
        }

        private static readonly Func<SocketAddress, byte[]> GetSocketAddressBuffer = GenGetSocketAddressBufferFunc();
        private static readonly Func<IPAddress, SocketAddress> CreateSocketAddressByIpAddress = GenCreateSocketAddressByIpAddressFunc();

        private static Guid GetPreferredPublicGuid()
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            var hostInfo = Dns.GetHostEntry("www.baidu.com");
            var ipAddr = hostInfo.AddressList[0];
            var sa = CreateSocketAddressByIpAddress(ipAddr);
            var sabuffer = GetSocketAddressBuffer(sa);

            NativeMethods.GetBestInterfaceEx(sabuffer, out uint bestIfIndex);

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

        // ReSharper disable once UnusedMember.Local
        private static Func<SocketAddress, byte[]> GenGetSocketAddressBufferFuncEmit()
        {
            var dm = new DynamicMethod("GetSocketAddressBuffer", typeof(byte[]), new[] { typeof(SocketAddress) }, typeof(SocketAddress));
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

        // ReSharper disable once UnusedMember.Local
        private static Func<IPAddress, SocketAddress> GenCreateSocketAddressByIpAddressFuncEmit()
        {
            var dm = new DynamicMethod("CreateSocketAddressByIpAddress", typeof(SocketAddress), new[] { typeof(IPAddress) }, typeof(SocketAddress));
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

        private static Func<SocketAddress, byte[]> GenGetSocketAddressBufferFunc()
        {
            var type = typeof(SocketAddress);
            var field = type.GetField("m_Buffer", BindingFlags.Instance | BindingFlags.NonPublic);
            if (field == null)
            {
                throw new Exception("Api Broken");
            }
            var param = Expression.Parameter(type);
            var getfield = Expression.Field(param, field);
            var lambda = Expression.Lambda(typeof(Func<SocketAddress, byte[]>), getfield, param);
            return (Func<SocketAddress, byte[]>)lambda.Compile();
        }

        private static Func<IPAddress, SocketAddress> GenCreateSocketAddressByIpAddressFunc()
        {
            var type = typeof(SocketAddress);
            var ctor = type.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new[] { typeof(IPAddress) }, null);
            if (ctor == null)
            {
                throw new Exception("Api Broken");
            }

            var param = Expression.Parameter(typeof(IPAddress));
            var create = Expression.New(ctor, param);
            var lamdba = Expression.Lambda(typeof(Func<IPAddress, SocketAddress>), create, param);
            return (Func<IPAddress, SocketAddress>)lamdba.Compile();
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
