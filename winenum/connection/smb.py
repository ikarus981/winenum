"""SMB transport for authenticated registry reads."""

import struct

from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.dcerpc.v5 import transport, rrp

from .registry import (
    ACCESS_DENIED,
    NOT_FOUND,
    UNAVAILABLE,
    VALUE,
    RegistryResult,
    not_found_result,
    unavailable_result,
    value_result,
)


class SMBTransport:
    """Read selected registry values through MS-RRP over SMB."""

    HIVE_MAP = {
        'HKLM': 'HKLM',
        'HKEY_LOCAL_MACHINE': 'HKLM',
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
        self.registry_ok = False
        self.smb = None
        self.reg_dce = None
        self.reg_handle = None

    def connect(self):
        try:
            self.smb = SMBConnection(self.target, self.target)
            if self.use_kerberos or self.aes_key:
                self.smb.kerberosLogin(
                    self.username, self.password, self.domain,
                    self.lmhash, self.nthash, self.aes_key,
                    kdcHost=self.dc_ip or None,
                )
            elif not self.password and (self.lmhash or self.nthash):
                # pass-the-hash
                self.smb.login(self.username, '', self.domain,
                               self.lmhash, self.nthash)
            else:
                self.smb.login(self.username, self.password, self.domain)
            self.connected = True
            self._connect_registry()
            return True
        except Exception as e:
            if self.console:
                self.console.debug_msg(f"SMB connection failed: {e}")
            return False

    def _connect_registry(self):
        """Attach to RemoteRegistry via \\PIPE\\winreg (MS-RRP).

        Reuses the already-authenticated SMB channel (transport.SMBTransport with
        smb_connection) rather than opening a second independent SMB session;
        the standalone ncacn_np factory frequently returns
        STATUS_PIPE_NOT_AVAILABLE even when RemoteRegistry is running.
        """
        try:
            rpctransport = transport.SMBTransport(
                remoteName=self.target,
                filename=r'\winreg',
                remote_host=self.target,
                smb_connection=self.smb,
            )
            self.reg_dce = rpctransport.get_dce_rpc()
            self.reg_dce.connect()
            self.reg_dce.bind(rrp.MSRPC_UUID_RRP)
            resp = rrp.hOpenLocalMachine(self.reg_dce)
            self.reg_handle = resp['phKey']
            self.registry_ok = True
        except Exception as e:
            # RemoteRegistry disabled/pipe unavailable on some targets;
            # The connection manager can fall back to WMI in that case.
            self.registry_ok = False
            if self.console:
                self.console.debug_msg(f"RemoteRegistry unavailable: {e}")

    def execute(self, command):
        return None

    def _split_key(self, key_path):
        """Split 'HKLM\\a\\b' into (hive, subkey) or (None, None) if hive unsupported."""
        parts = key_path.split('\\')
        hive = parts[0].upper()
        if self.HIVE_MAP.get(hive) is None:
            return None, None
        return hive, '\\'.join(parts[1:])

    def key_exists(self, key_path):
        """Return True if the registry key exists (independently of values)."""
        if not (self.connected and self.registry_ok):
            return False
        hive, subkey = self._split_key(key_path)
        if not subkey:
            return False
        try:
            resp = rrp.hBaseRegOpenKey(self.reg_dce, self.reg_handle, subkey)
            try:
                rrp.hBaseRegCloseKey(self.reg_dce, resp['phkResult'])
            except Exception:
                pass
            return True
        except Exception:
            return False

    def value_exists(self, key_path, value_name):
        """Return True if the named value exists under the key.

        A missing key (ERROR_FILE_NOT_FOUND / 0x2) on hBaseRegOpenKey, or a
        missing value on hBaseRegQueryValue, both mean 'not configured'.
        Any other transport error also returns False.
        """
        if not (self.connected and self.registry_ok):
            return False
        hive, subkey = self._split_key(key_path)
        if not subkey:
            return False
        try:
            resp = rrp.hBaseRegOpenKey(self.reg_dce, self.reg_handle, subkey)
            key_handle = resp['phkResult']
        except Exception:
            return False
        try:
            rrp.hBaseRegQueryValue(self.reg_dce, key_handle, value_name)
            return True
        except Exception:
            return False
        finally:
            try:
                rrp.hBaseRegCloseKey(self.reg_dce, key_handle)
            except Exception:
                pass

    def read_registry_result(self, key_path, value_name):
        """Read one value through MS-RRP and preserve the evidence state."""
        if not (self.connected and self.registry_ok):
            return unavailable_result('ms-rrp', 'registry transport unavailable')
        hive, subkey = self._split_key(key_path)
        if not subkey:
            return unavailable_result('ms-rrp', 'unsupported registry path')
        try:
            response = rrp.hBaseRegOpenKey(self.reg_dce, self.reg_handle, subkey)
            key_handle = response['phkResult']
            try:
                raw_value = rrp.hBaseRegQueryValue(
                    self.reg_dce, key_handle, value_name
                )
            finally:
                try:
                    rrp.hBaseRegCloseKey(self.reg_dce, key_handle)
                except Exception:
                    pass
        except Exception as exc:
            code = getattr(getattr(exc, 'error_code', None), 'value', None)
            if code is None:
                code = getattr(exc, 'error_code', None)
            not_found = code in (2, '2', '0x2') or 'ERROR_FILE_NOT_FOUND' in str(exc)
            if not_found:
                return not_found_result('ms-rrp')
            access_denied = code in (5, '5', '0x5') or 'ACCESS_DENIED' in str(exc).upper()
            if self.console:
                self.console.debug_msg(
                    f"Registry read failed ({key_path}\\{value_name}): {exc}")
            return unavailable_result('ms-rrp', str(exc), access_denied)

        if isinstance(raw_value, (tuple, list)) and len(raw_value) >= 2:
            reg_type = raw_value[-2]
            data = raw_value[-1]
        else:
            reg_type, data = None, raw_value
        return value_result(self._parse_value(reg_type, data), 'ms-rrp', reg_type)

    def get_registry_value(self, key_path, value_name):
        """Return a value, REG_NOT_FOUND, or None when MS-RRP is unavailable."""
        from ..utils import REG_NOT_FOUND
        result = self.read_registry_result(key_path, value_name)
        if result.state == VALUE:
            return result.value
        if result.state == NOT_FOUND:
            return REG_NOT_FOUND
        return None


    def _parse_value(self, reg_type, data):
        if isinstance(data, str):
            return data
        if reg_type in (1, 2) and isinstance(data, (bytes, bytearray)):
            return data.decode('utf-16-le', errors='replace').rstrip('\x00')
        if reg_type == 4:
            if isinstance(data, (bytes, bytearray)):
                return struct.unpack('<I', data)[0]
            try:
                return int(data)
            except (TypeError, ValueError):
                return data
        if reg_type == 7 and isinstance(data, (bytes, bytearray)):
            text = data.decode('utf-16-le', errors='replace').rstrip('\x00')
            return [v for v in text.split('\x00') if v]
        return data

    def get_capabilities(self):
        return {
            'smb': bool(self.connected),
            'registry': bool(self.registry_ok),
            'registry_source': 'ms-rrp' if self.registry_ok else 'none',
        }

    def get_smb_signing(self):
        """Check SMB signing status"""
        if not self.smb:
            return 'UNKNOWN'
        try:
            signing = self.smb.isSigningRequired()
            return 'REQUIRED' if signing else 'NOT REQUIRED'
        except Exception:
            return 'UNKNOWN'

    def get_smb_version(self):
        """Get SMB dialect version"""
        if not self.smb:
            return 'UNKNOWN'
        try:
            dialect = self.smb.getDialect()
            if dialect == SMB_DIALECT:
                return 'SMBv1'
            versions = {
                0x0202: 'SMBv2.0.2',
                0x0210: 'SMBv2.1',
                0x0300: 'SMBv3.0',
                0x0302: 'SMBv3.0.2',
                0x0311: 'SMBv3.1.1',
            }
            return versions.get(dialect, f'0x{dialect:04x}')
        except Exception:
            return 'UNKNOWN'

    def close(self):
        if self.reg_dce:
            try:
                self.reg_dce.disconnect()
            except Exception:
                pass
        if self.smb:
            try:
                self.smb.close()
            except Exception:
                pass
        self.connected = False
        self.registry_ok = False
