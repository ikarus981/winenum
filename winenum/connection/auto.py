"""Select the least invasive available authenticated transport."""

import socket

from .composite import CompositeTransport
from .rpc import RPCTransport
from .smb import SMBTransport
from .wmi import WMITransport


class TransportManager:
    """Probe and manage SMB, WMI/DCOM, and MS-RPC transports."""

    def __init__(self, target, username='', password='', domain='', console=None,
                 timeout=10):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.console = console
        self.timeout = timeout
        self.connection = None
        self.transport_type = None
        self.os_type = None
        self._smb_no_registry = None

    @property
    def host(self):
        return self.target

    def check_port(self, host, port, timeout=None):
        timeout = self.timeout if timeout is None else timeout
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def get_open_ports(self):
        ports = {
            445: 'SMB',
            135: 'WMI/RPC',
            5985: 'WinRM HTTP',
            5986: 'WinRM HTTPS',
            3389: 'RDP',
            22: 'SSH',
            389: 'LDAP',
            636: 'LDAPS',
            88: 'Kerberos',
        }
        return {
            port: name
            for port, name in ports.items()
            if self.check_port(self.target, port)
        }

    def detect_os_type(self, transport):
        """Detect server/client from the WMI OS caption."""
        if hasattr(transport, 'get_operating_system'):
            try:
                results = transport.get_operating_system()
                for result in results or []:
                    caption = getattr(result, 'Caption', '')
                    if caption:
                        self.os_type = 'server' if 'server' in caption.lower() else 'client'
                        return
            except Exception:
                pass
        self.os_type = 'unknown'

    def _new_smb(self, auth_kwargs):
        return SMBTransport(
            self.target,
            self.username,
            self.password,
            self.domain,
            self.console,
            **auth_kwargs,
        )

    def _new_wmi(self, auth_kwargs):
        return WMITransport(
            self.target,
            self.username,
            self.password,
            self.domain,
            self.console,
            **auth_kwargs,
        )

    def auto_connect(self, username=None, password=None, domain=None,
                     lmhash='', nthash='', aes_key='', dc_ip='',
                     use_kerberos=False):
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password
        if domain is not None:
            self.domain = domain

        auth_kwargs = {
            'lmhash': lmhash,
            'nthash': nthash,
            'aes_key': aes_key,
            'dc_ip': dc_ip,
            'use_kerberos': use_kerberos,
        }
        open_ports = self.get_open_ports()
        if self.console and not getattr(self.console, 'quiet', False):
            if self.console.debug:
                self.console.info(f"Checking ports on {self.target}...")
                for port, name in open_ports.items():
                    self.console.debug_msg(f"Port {port} ({name}): OPEN")
            else:
                self.console.info(f"Checking ports on {self.target}...")

        if 445 in open_ports:
            if self.console:
                self.console.debug_msg("Stage 1: SMB/MS-RRP registry transport...")
            smb = self._new_smb(auth_kwargs)
            if smb.connect():
                if smb.registry_ok:
                    self.connection = smb
                    self.transport_type = 'smb'
                    if self.console:
                        self.console.success("Connected via SMB/MS-RRP")
                    return self.connection
                self._smb_no_registry = smb
                if self.console:
                    self.console.debug_msg(
                        "SMB authentication succeeded, but Remote Registry is unavailable; trying WMI")
            else:
                smb.close()

        if 135 in open_ports:
            if self.console:
                self.console.debug_msg("Stage 2: WMI/DCOM transport...")
            wmi_transport = self._new_wmi(auth_kwargs)
            if wmi_transport.connect():
                self.detect_os_type(wmi_transport)
                if self.console:
                    self.console.success("Connected via WMI/DCOM")
                smb = self._smb_no_registry
                if smb is None and 445 in open_ports:
                    smb = self._new_smb(auth_kwargs)
                    if not smb.connect():
                        smb.close()
                        smb = None
                self.connection = CompositeTransport(wmi_transport, smb, self.console)
                self.transport_type = 'composite' if smb else 'wmi'
                return self.connection
            wmi_transport.close()

        if 445 in open_ports:
            if self.console:
                self.console.debug_msg("Stage 3: MS-RPC LSA transport...")
            rpc = RPCTransport(
                self.target,
                self.username,
                self.password,
                self.domain,
                self.console,
                **auth_kwargs,
            )
            if rpc.connect('lsarpc'):
                self.connection = rpc
                self.transport_type = 'rpc'
                if self.console:
                    self.console.success("Connected via MS-RPC")
                return self.connection
            rpc.close()

        if self._smb_no_registry:
            self._smb_no_registry.close()
            self._smb_no_registry = None
        if self.console:
            self.console.error(f"Failed to connect to {self.target}")
        return None
