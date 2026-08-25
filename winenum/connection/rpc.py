"""MS-RPC transport for selected LSA queries."""
from impacket.dcerpc.v5 import transport, lsat
try:
    from impacket.dcerpc.v5.dtypes import LSAPR_HANDLE
except ImportError:
    LSAPR_HANDLE = None


class RPCTransport:
    """Query selected LSA policy data through MS-RPC."""

    PIPE_MAP = {
        'lsarpc': r'\PIPE\lsarpc',
        'samr': r'\PIPE\samr',
        'netlogon': r'\PIPE\netlogon',
    }

    def __init__(self, target, username, password, domain='', console=None,
                 lmhash='', nthash='', aes_key='', dc_ip='', use_kerberos=False):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.console = console
        self.lmhash = lmhash or ''
        self.nthash = nthash or ''
        self.aes_key = aes_key or ''
        self.dc_ip = dc_ip or ''
        self.use_kerberos = bool(use_kerberos)
        self.connected = False
        self.smb = None
        self.dce = None

    def connect(self, pipe='lsarpc'):
        try:
            stringbinding = f'ncacn_np:{self.target}[\\PIPE\\{pipe}]'
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash, aesKey=self.aes_key,
            )
            if (self.use_kerberos or self.aes_key) and hasattr(rpctransport, 'set_kerberos'):
                rpctransport.set_kerberos(True, kdcHost=self.dc_ip or None)

            self.dce = rpctransport.get_dce_rpc()
            self.dce.connect()
            self.connected = True
            return True
        except Exception as e:
            if self.console:
                self.console.debug_msg(f"RPC connection failed: {e}")
            return False

    def lsar_open_policy(self):
        """Open LSA policy handle"""
        if not self.connected or not self.dce:
            return None
        try:
            from impacket.dcerpc.v5.dtypes import OBJECTATTRIBUTES
            objectAttributes = OBJECTATTRIBUTES()
            objectAttributes['ObjectName'] = None
            objectAttributes['Attributes'] = 0
            objectAttributes['SecurityDescriptor'] = None
            objectAttributes['SecurityQualityOfService'] = None
            resp = lsat.hLsarOpenPolicy2(self.dce, objectAttributes, lsat.POLICY_ALL_ACCESS)
            return resp
        except Exception as e:
            if self.console:
                self.console.debug_msg(f"LSA open policy failed: {e}")
            return None

    def query_lsa_policy(self, info_class):
        """Query LSA policy information"""
        if not self.connected:
            return None
        try:
            policy_handle = self.lsar_open_policy()
            if not policy_handle:
                return None
            resp = lsat.hLsarQueryInformationPolicy2(
                self.dce,
                policyHandle=policy_handle,
                informationClass=info_class
            )
            lsat.hLsarClose(self.dce, policy_handle)
            return resp
        except Exception as e:
            if self.console:
                self.console.debug_msg(f"LSA query failed: {e}")
            return None

    def lsar_lookup_names(self, names):
        """Lookup names via LSA (detects services)"""
        if not self.connected:
            return None
        try:
            resp = lsat.hLsarLookupNames2(
                self.dce,
                names=names
            )
            return resp
        except Exception as e:
            if self.console:
                self.console.debug_msg(f"LSA lookup names failed: {e}")
            return None

    def check_service_installed(self, service_name):
        """Check if a service is installed via LsarLookupNames"""
        try:
            full_name = f'NT Service\\{service_name}'
            resp = self.lsar_lookup_names([full_name])
            if resp and 'ReferencedDomainsList' in resp:
                return True
            return False
        except:
            return False

    def get_system_info(self):
        """Get system info via LSA policy"""
        if not self.connected:
            return {}
        try:
            info = {}
            resp = self.query_lsa_policy(5)  # PolicyDnsDomainInformation
            if resp and 'PolicyInformation' in resp:
                domain_info = resp['PolicyInformation']
                if 'DnsDomainName' in domain_info:
                    info['domain'] = domain_info['DnsDomainName']['Buffer'].decode('utf-16-le')
                if 'Sid' in domain_info:
                    info['domain_sid'] = str(domain_info['Sid'])
            return info
        except:
            return {}

    def get_capabilities(self):
        return {
            'rpc': bool(self.connected),
            'registry': False,
            'registry_source': 'none',
        }

    def execute(self, command):
        return None

    def get_registry_value(self, key_path, value_name):
        return None

    def close(self):
        if self.dce:
            try:
                self.dce.disconnect()
            except:
                pass
        if self.smb:
            try:
                self.smb.close()
            except:
                pass
        self.connected = False
