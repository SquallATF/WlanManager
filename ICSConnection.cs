using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NETCONLib;

namespace WlanManager
{
    class ICSConnection
    {
        private readonly INetConnectionProps _netConnectionProperties;
        private readonly INetSharingConfiguration _netSharingConfiguration;

        public ICSConnection(INetSharingManager nsManager, INetConnection netConnection)
        {
            if (nsManager == null)
            {
                throw new ArgumentNullException(nameof(nsManager));
            }

            if (netConnection == null)
            {
                throw new ArgumentNullException(nameof(netConnection));
            }

            _netConnectionProperties = nsManager.NetConnectionProps[netConnection];
            _netSharingConfiguration = nsManager.INetSharingConfigurationForINetConnection[netConnection];
        }

        public string InterfaceId => _netConnectionProperties.Guid;

        public bool IsSupported => _netConnectionProperties.MediaType == tagNETCON_MEDIATYPE.NCM_LAN;

        public bool IsAvailable => _netConnectionProperties.Status != tagNETCON_STATUS.NCS_DISCONNECTED;

        public bool IsEnabled => _netSharingConfiguration.SharingEnabled;

        public bool IsPublicEnabled => _netSharingConfiguration.SharingEnabled
                                         && _netSharingConfiguration.SharingConnectionType == tagSHARINGCONNECTIONTYPE.ICSSHARINGTYPE_PUBLIC;

        public bool IsPrivateEnabled => _netSharingConfiguration.SharingEnabled
                                          && _netSharingConfiguration.SharingConnectionType == tagSHARINGCONNECTIONTYPE.ICSSHARINGTYPE_PRIVATE;

        public void EnableAsPublic()
        {
            DisableSharing();
            _netSharingConfiguration.EnableSharing(tagSHARINGCONNECTIONTYPE.ICSSHARINGTYPE_PUBLIC);
        }

        public void EnableAsPrivate()
        {
            DisableSharing();
            _netSharingConfiguration.EnableSharing(tagSHARINGCONNECTIONTYPE.ICSSHARINGTYPE_PRIVATE);
        }

        public void DisableSharing()
        {
            if (!IsEnabled)
            {
                return;
            }

            _netSharingConfiguration.DisableSharing();
        }
    }
}
