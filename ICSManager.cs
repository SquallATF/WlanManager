using System;
using System.Collections.Generic;
using System.ServiceProcess;
using NETCONLib;

namespace WlanManager
{
    class ICSManager : IDisposable
    {
        private readonly INetSharingManager _netSharingManager;
        private readonly ServiceController _icsService;

        public ICSManager()
        {
            _netSharingManager = new NetSharingManager();

            if (!_netSharingManager.SharingInstalled)
            {
                var message = Environment.OSVersion.Version.Major == 5
                    ? "The operating system doesn't support connection sharing"
                    : "ICS requires elevated privilege";
                throw new NotSupportedException(message);
            }

            _icsService = new ServiceController("SharedAccess");
        }

        public void Dispose()
        {
            _icsService.Dispose();
        }

        public IDictionary<Guid, ICSConnection> Connections
        {
            get
            {
                var dictionary = new Dictionary<Guid, ICSConnection>();

                foreach (INetConnection conn in _netSharingManager.EnumEveryConnection)
                {
                    var icsConnection = new ICSConnection(_netSharingManager, conn);
                    dictionary.Add(new Guid(icsConnection.InterfaceId), icsConnection);
                }

                return dictionary;
            }
        }

        public bool IsServiceStatusValid => _icsService.Status != ServiceControllerStatus.StartPending
                                              && _icsService.Status != ServiceControllerStatus.StopPending;

        public void EnableSharing(Guid publicGuid, Guid privateGuid)
        {
            if (!Connections.ContainsKey(publicGuid))
            {
                throw new ArgumentException("The connection with publicGuid was not found.");
            }

            if (!Connections.ContainsKey(privateGuid))
            {
                throw new ArgumentException("The connection with privateGuid was not found.");
            }

            var publicConnection = Connections[publicGuid];
            var privateConnection = Connections[privateGuid];
            if (publicConnection.IsPublicEnabled
                && privateConnection.IsPrivateEnabled)
            {
                return;
            }

            DisableAllSharing();
            publicConnection.EnableAsPublic();
            privateConnection.EnableAsPrivate();
        }

        private void DisableAllSharing()
        {
            foreach (var connection in Connections.Values)
            {
                if (connection.IsSupported)
                {
                    connection.DisableSharing();
                }
            }
        }
    }
}
