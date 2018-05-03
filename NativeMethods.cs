using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WlanManager
{
    static class NativeMethods
    {
        static readonly int WLAN_INTERFACE_INFO_SIZE = Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO));
        static readonly int WLAN_PROFILE_INFO_SIZE = Marshal.SizeOf(typeof(WLAN_PROFILE_INFO));
        static readonly int WLAN_HOSTED_NETWORK_PEER_STATE_SIZE = Marshal.SizeOf(typeof(WLAN_HOSTED_NETWORK_PEER_STATE));

        public const uint WLAN_API_VERSION_1_0 = 0x00000001;
        public const uint WLAN_API_VERSION_2_0 = 0x00000002;

        public const uint WLAN_PROFILE_GROUP_POLICY = 0x00000001;
        public const uint WLAN_PROFILE_USER = 0x00000002;
        public const uint WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000004;

        public const uint ERROR_SUCCESS = 0;
        public const uint ERROR_BAD_CONFIGURATION = 1610;
        public const uint ERROR_SERVICE_NOT_ACTIVE = 1062;


        public const uint WLAN_NOTIFICATION_SOURCE_NONE = 0;
        public const uint WLAN_NOTIFICATION_SOURCE_ONEX = 0x00000004;
        public const uint WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008;
        public const uint WLAN_NOTIFICATION_SOURCE_MSM = 0x00000010;
        public const uint WLAN_NOTIFICATION_SOURCE_SECURITY = 0x00000020;
        public const uint WLAN_NOTIFICATION_SOURCE_IHV = 0x00000040;
        public const uint WLAN_NOTIFICATION_SOURCE_HNWK = 0x00000080;
        public const uint WLAN_NOTIFICATION_SOURCE_ALL = 0x0000FFFF;

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_INTERFACE_INFO_LIST
        {
            public uint dwNumberOfItems;
            public uint dwIndex;
            public WLAN_INTERFACE_INFO[] InterfaceInfo;

            public WLAN_INTERFACE_INFO_LIST(IntPtr pList)
            {
                dwNumberOfItems = (uint)Marshal.ReadInt32(pList, 0);
                dwIndex = (uint)Marshal.ReadInt32(pList, 4);
                InterfaceInfo = new WLAN_INTERFACE_INFO[dwNumberOfItems];

                for (int i = 0; i < dwNumberOfItems; i++)
                {
                    IntPtr pItemList = new IntPtr(pList.ToInt64() + (i * WLAN_INTERFACE_INFO_SIZE) + 8);
                    InterfaceInfo[i] = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(pItemList, typeof(WLAN_INTERFACE_INFO));
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_INTERFACE_INFO
        {
            [MarshalAs(UnmanagedType.Struct)]
            public Guid InterfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;
            public WLAN_INTERFACE_STATE isState;
        }

        public enum WLAN_INTERFACE_STATE
        {
            wlan_interface_state_not_ready = 0,
            wlan_interface_state_connected = 1,
            wlan_interface_state_ad_hoc_network_formed = 2,
            wlan_interface_state_disconnecting = 3,
            wlan_interface_state_disconnected = 4,
            wlan_interface_state_associating = 5,
            wlan_interface_state_discovering = 6,
            wlan_interface_state_authenticating = 7
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_PROFILE_INFO_LIST
        {
            public uint dwNumberOfItems;
            public uint dwIndex;
            public WLAN_PROFILE_INFO[] ProfileInfo;

            public WLAN_PROFILE_INFO_LIST(IntPtr pList)
            {
                dwNumberOfItems = (uint)Marshal.ReadInt32(pList, 0);
                dwIndex = (uint)Marshal.ReadInt32(pList, 4);
                ProfileInfo = new WLAN_PROFILE_INFO[dwNumberOfItems];

                for (int i = 0; i < dwNumberOfItems; i++)
                {
                    IntPtr pItemList = new IntPtr(pList.ToInt64() + (i * WLAN_PROFILE_INFO_SIZE) + 8);
                    ProfileInfo[i] = (WLAN_PROFILE_INFO)Marshal.PtrToStructure(pItemList, typeof(WLAN_PROFILE_INFO));
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_PROFILE_INFO
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strProfileName;
            public uint dwFlags;
        }

        public enum WLAN_HOSTED_NETWORK_OPCODE
        {
            wlan_hosted_network_opcode_connection_settings,
            wlan_hosted_network_opcode_security_settings,
            wlan_hosted_network_opcode_station_profile,
            wlan_hosted_network_opcode_enable
        }

        public enum WLAN_OPCODE_VALUE_TYPE
        {
            wlan_opcode_value_type_query_only = 0,
            wlan_opcode_value_type_set_by_group_policy = 1,
            wlan_opcode_value_type_set_by_user = 2,
            wlan_opcode_value_type_invalid = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS
        {
            public DOT11_SSID hostedNetworkSSID;
            public uint dwMaxNumberOfPeers;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct DOT11_SSID
        {
            public uint uSSIDLength;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string ucSSID;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_HOSTED_NETWORK_SECURITY_SETTINGS
        {
            public DOT11_AUTH_ALGORITHM dot11AuthAlgo;
            public DOT11_CIPHER_ALGORITHM dot11CipherAlgo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_NOTIFICATION_DATA
        {
            public uint NotificationSource;
            public WLAN_HOSTED_NETWORK_NOTIFICATION_CODE NotificationCode;
            public Guid InterfaceGuid;
            public uint dwDataSize;
            public IntPtr pData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_HOSTED_NETWORK_STATE_CHANGE
        {
            public WLAN_HOSTED_NETWORK_STATE OldState;
            public WLAN_HOSTED_NETWORK_STATE NewState;
            public WLAN_HOSTED_NETWORK_REASON StateChangeReason;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_HOSTED_NETWORK_DATA_PEER_STATE_CHANGE
        {
            public WLAN_HOSTED_NETWORK_PEER_STATE OldState;
            public WLAN_HOSTED_NETWORK_PEER_STATE NewState;
            public WLAN_HOSTED_NETWORK_REASON StateChangeReason;
        }

        public enum DOT11_AUTH_ALGORITHM : uint
        {
            DOT11_AUTH_ALGO_80211_OPEN = 1,
            DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
            DOT11_AUTH_ALGO_WPA = 3,
            DOT11_AUTH_ALGO_WPA_PSK = 4,
            DOT11_AUTH_ALGO_WPA_NONE = 5,               // used in NatSTA only
            DOT11_AUTH_ALGO_RSNA = 6,
            DOT11_AUTH_ALGO_RSNA_PSK = 7,
            DOT11_AUTH_ALGO_IHV_START = 0x80000000,
            DOT11_AUTH_ALGO_IHV_END = 0xffffffff
        }

        public enum DOT11_CIPHER_ALGORITHM : uint
        {
            DOT11_CIPHER_ALGO_NONE = 0x00,
            DOT11_CIPHER_ALGO_WEP40 = 0x01,
            DOT11_CIPHER_ALGO_TKIP = 0x02,
            DOT11_CIPHER_ALGO_CCMP = 0x04,
            DOT11_CIPHER_ALGO_WEP104 = 0x05,
            DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
            DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
            DOT11_CIPHER_ALGO_WEP = 0x101,
            DOT11_CIPHER_ALGO_IHV_START = 0x80000000,
            DOT11_CIPHER_ALGO_IHV_END = 0xffffffff
        }

        public enum WLAN_HOSTED_NETWORK_NOTIFICATION_CODE : uint
        {
            wlan_hosted_network_state_change = 0x00001000,
            wlan_hosted_network_peer_state_change,
            wlan_hosted_network_radio_state_change
        }


        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct WLAN_HOSTED_NETWORK_STATUS
        {
            public WLAN_HOSTED_NETWORK_STATE HostedNetworkState;
            public Guid IPDeviceID;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] wlanHostedNetworkBSSID;
            public DOT11_PHY_TYPE dot11PhyType;
            public uint ulChannelFrequency;
            public uint dwNumberOfPeers;
            public WLAN_HOSTED_NETWORK_PEER_STATE[] PeerList;

            public WLAN_HOSTED_NETWORK_STATUS(IntPtr pStatus)
            {
                HostedNetworkState = (WLAN_HOSTED_NETWORK_STATE)Marshal.ReadInt32(pStatus, 0);
                IPDeviceID = (Guid)Marshal.PtrToStructure(new IntPtr(pStatus.ToInt64() + 4), typeof(Guid));
                wlanHostedNetworkBSSID = new byte[6];
                Marshal.Copy(new IntPtr(pStatus.ToInt64() + 4 + 16), wlanHostedNetworkBSSID, 0, 6);
                dot11PhyType = (DOT11_PHY_TYPE)Marshal.ReadInt32(pStatus, 4 + 16 + 6 + 2); //pack 4
                ulChannelFrequency = (uint)Marshal.ReadInt32(pStatus, 4 + 16 + 6 + 2 + 4);
                dwNumberOfPeers = (uint)Marshal.ReadInt32(pStatus, 4 + 16 + 6 + 2 + 4 + 4);
                PeerList = new WLAN_HOSTED_NETWORK_PEER_STATE[dwNumberOfPeers];
                for (int i = 0; i < dwNumberOfPeers; i++)
                {
                    IntPtr pPeerItem = new IntPtr(pStatus.ToInt64() + 4 + 16 + 6 + 2 + 4 + 4 + 4 + (i * WLAN_HOSTED_NETWORK_PEER_STATE_SIZE));
                    PeerList[i] = (WLAN_HOSTED_NETWORK_PEER_STATE)Marshal.PtrToStructure(pPeerItem, typeof(WLAN_HOSTED_NETWORK_PEER_STATE));
                }
            }
        }

        public enum WLAN_HOSTED_NETWORK_STATE
        {
            wlan_hosted_network_unavailable,
            wlan_hosted_network_idle,
            wlan_hosted_network_active,
        }

        public enum DOT11_PHY_TYPE : uint
        {
            dot11_phy_type_unknown = 0,
            dot11_phy_type_any = dot11_phy_type_unknown,
            dot11_phy_type_fhss = 1,
            dot11_phy_type_dsss = 2,
            dot11_phy_type_irbaseband = 3,
            dot11_phy_type_ofdm = 4,
            dot11_phy_type_hrdsss = 5,
            dot11_phy_type_erp = 6,
            dot11_phy_type_ht = 7,
            dot11_phy_type_IHV_start = 0x80000000,
            dot11_phy_type_IHV_end = 0xffffffff
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct WLAN_HOSTED_NETWORK_PEER_STATE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] PeerMacAddress;
            public WLAN_HOSTED_NETWORK_PEER_AUTH_STATE PeerAuthState;
        }

        public enum WLAN_HOSTED_NETWORK_PEER_AUTH_STATE
        {
            wlan_hosted_network_peer_state_invalid,
            wlan_hosted_network_peer_state_authenticated,
        }

        public enum WLAN_HOSTED_NETWORK_REASON
        {
            wlan_hosted_network_reason_success = 0,
            wlan_hosted_network_reason_unspecified,
            wlan_hosted_network_reason_bad_parameters,
            wlan_hosted_network_reason_service_shutting_down,
            wlan_hosted_network_reason_insufficient_resources,
            wlan_hosted_network_reason_elevation_required,
            wlan_hosted_network_reason_read_only,
            wlan_hosted_network_reason_persistence_failed,
            wlan_hosted_network_reason_crypt_error,
            wlan_hosted_network_reason_impersonation,
            wlan_hosted_network_reason_stop_before_start,

            wlan_hosted_network_reason_interface_available,
            wlan_hosted_network_reason_interface_unavailable,
            wlan_hosted_network_reason_miniport_stopped,
            wlan_hosted_network_reason_miniport_started,
            wlan_hosted_network_reason_incompatible_connection_started,
            wlan_hosted_network_reason_incompatible_connection_stopped,
            wlan_hosted_network_reason_user_action,
            wlan_hosted_network_reason_client_abort,
            wlan_hosted_network_reason_ap_start_failed,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DEV_BROADCAST_HDR
        {
            public uint dbch_size;
            public uint dbch_devicetype;
            public uint dbch_reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct DEV_BROADCAST_DEVICEINTERFACE
        {
            public uint dbch_size;
            public uint dbch_devicetype;
            public uint dbch_reserved;
            [MarshalAs(UnmanagedType.Struct)]
            public Guid dbcc_classguid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 255)]
            public string dbcc_name;
        }

        //[DllImport("wlanapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        //public static extern uint WlanGetProfile(
        //    [In]IntPtr hClientHandle,
        //    [In, MarshalAs(UnmanagedType.LPStruct)]Guid pInterfaceGuid,
        //    [In, MarshalAs(UnmanagedType.LPWStr)]string strProfileName,
        //    IntPtr pReserved,
        //    [Out]out IntPtr pstrProfileXml,
        //    [In, Out, Optional]ref uint pdwFlags,
        //    [Out, Optional]out uint pdwGrantedAccess);

        //[DllImport("wlanapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        //public static extern uint WlanGetProfile(
        //    [In]IntPtr hClientHandle,
        //    [In, MarshalAs(UnmanagedType.LPStruct)]Guid pInterfaceGuid,
        //    [In, MarshalAs(UnmanagedType.LPWStr)]string strProfileName,
        //    IntPtr pReserved,
        //    [Out]out IntPtr pstrProfileXml,
        //    [In, Out, Optional]IntPtr pdwFlags,
        //    [Out, Optional]out uint pdwGrantedAccess);

        [DllImport("wlanapi.dll")]
        public static extern uint WlanOpenHandle(
            [In] uint dwClientVersion,
            IntPtr pReserved,
            [Out] out uint pdwNegotiatedVersion,
            [Out] out WlanHandle phClientHandle);

        [DllImport("wlanapi.dll")]
        public static extern uint WlanCloseHandle(
            [In] IntPtr hClientHandle,
            IntPtr pReserved = default(IntPtr));

        //[DllImport("wlanapi.dll")]
        //public static extern uint WlanEnumInterfaces([In] IntPtr hClientHandle, [In] IntPtr pReserved, [Out] out IntPtr ppInterfaceList);

        //[DllImport("wlanapi.dll")]
        //public static extern uint WlanGetProfileList([In] IntPtr hClientHandle, [In, MarshalAs(UnmanagedType.LPStruct)] Guid pInterfaceGuid, [In] IntPtr pReserved, [Out] out IntPtr ppProfileList);

        [DllImport("wlanapi.dll")]
        public static extern void WlanFreeMemory([In] IntPtr pMemory);

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkStartUsing(
            [In] WlanHandle hClientHandle,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkStopUsing(
            [In] WlanHandle hClientHandle,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkForceStart(
            [In] WlanHandle hClientHandle,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkForceStop(
            [In] WlanHandle hClientHandle,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkQueryProperty(
            [In] WlanHandle hClientHandle,
            [In] WLAN_HOSTED_NETWORK_OPCODE OpCode,
            [Out] out uint pdwDataSize,
            [Out] out IntPtr ppvData,
            [Out] out WLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkSetProperty(
            [In] WlanHandle hClientHandle,
            [In] WLAN_HOSTED_NETWORK_OPCODE OpCode,
            [In] uint dwDataSize,
            [In] IntPtr pvData,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkInitSettings(
            [In] WlanHandle hClientHandle,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkRefreshSecuritySettings(
            [In] WlanHandle hClientHandle,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkQueryStatus(
            [In] WlanHandle hClientHandle,
            [Out] out IntPtr ppWlanHostedNetworkStatus,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkSetSecondaryKey(
            [In] WlanHandle hClientHandle,
            [In] uint dwKeyLength,
            [In, MarshalAs(UnmanagedType.LPStr)] string pucKeyData,
            [In, MarshalAs(UnmanagedType.Bool)] bool bIsPassPhrase,
            [In, MarshalAs(UnmanagedType.Bool)] bool bPersistent,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        [DllImport("wlanapi.dll")]
        public static extern uint WlanHostedNetworkQuerySecondaryKey(
            [In] WlanHandle hClientHandle,
            [Out] out uint pdwKeyLength,
            [Out] out IntPtr ppucKeyData,
            [Out, MarshalAs(UnmanagedType.Bool)] out bool pbIsPassPhrase,
            [Out, MarshalAs(UnmanagedType.Bool)] out bool pbPersistent,
            [Out, Optional] out WLAN_HOSTED_NETWORK_REASON pFailReason,
            IntPtr pvReserved = default(IntPtr));

        public delegate void WLAN_NOTIFICATION_CALLBACK(WLAN_NOTIFICATION_DATA data, IntPtr context);

        [DllImport("wlanapi.dll")]
        public static extern uint WlanRegisterNotification(
            [In] WlanHandle hClientHandle,
            [In] uint dwNotifSource,
            [In, MarshalAs(UnmanagedType.Bool)] bool bIgnoreDuplicate,
            [In, Optional] WLAN_NOTIFICATION_CALLBACK funcCallback,
            [In, Optional] IntPtr pCallbackContext,
            IntPtr pReserved,
            [Out, Optional] out uint pdwPrevNotifSource);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr RegisterDeviceNotification(
            [In]IntPtr hRecipient,
            [In]IntPtr NotificationFilter,
            [In]uint Flags);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnregisterDeviceNotification(
            [In]IntPtr Handle);

        [DllImport("Iphlpapi.dll")]
        public static extern uint GetBestInterfaceEx([In]byte[] pDestAddr, [Out]out uint dwBestIfIndex);
    }
}
