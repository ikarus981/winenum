"""Composite WMI and registry transport."""

from .registry import NOT_FOUND, UNAVAILABLE, VALUE


class CompositeTransport:
    """Combine WMI/DCOM with the best available registry reader."""

    def __init__(self, wmi_transport, smb_transport=None, console=None):
        self.wmi = wmi_transport
        self.smb = smb_transport
        self.console = console
        self.target = wmi_transport.target
        self.registry_ok = bool(
            (smb_transport and smb_transport.registry_ok)
            or getattr(wmi_transport, 'registry_ok', False)
        )
        self.registry_source = (
            'ms-rrp' if smb_transport and smb_transport.registry_ok
            else getattr(wmi_transport, 'registry_source', 'none')
        )
        self.last_registry_result = None

    def get_device_guard(self):
        return self.wmi.get_device_guard()

    def get_operating_system(self):
        return self.wmi.get_operating_system()

    def get_computer_system(self):
        return self.wmi.get_computer_system()

    def wmi_query(self, wmi_class, properties=None, namespace='root\\cimv2'):
        return self.wmi.wmi_query(wmi_class, properties, namespace)

    def read_registry_result(self, key_path, value_name):
        """Read through MS-RRP, then StdRegProv only when needed."""
        result = None
        if self.smb and self.smb.registry_ok:
            if hasattr(self.smb, 'read_registry_result'):
                result = self.smb.read_registry_result(key_path, value_name)
            if result and result.state in (VALUE, NOT_FOUND):
                self.registry_ok = True
                self.registry_source = 'ms-rrp'
                self.last_registry_result = result
                return result

        if hasattr(self.wmi, 'read_registry_result'):
            result = self.wmi.read_registry_result(key_path, value_name)
        if result:
            self.registry_ok = result.readable
            self.registry_source = result.source
        self.last_registry_result = result
        return result

    def get_registry_value(self, key_path, value_name):
        """Return a value, REG_NOT_FOUND, or None for an unavailable source."""
        from ..utils import REG_NOT_FOUND
        result = self.read_registry_result(key_path, value_name)
        if result is None or result.state == UNAVAILABLE:
            return None
        if result.state == NOT_FOUND:
            return REG_NOT_FOUND
        if result.state == VALUE:
            return result.value
        return None

    def key_exists(self, key_path):
        if self.smb and self.smb.registry_ok and self.smb.key_exists(key_path):
            return True
        return self.wmi.key_exists(key_path)

    def value_exists(self, key_path, value_name):
        from ..utils import REG_NOT_FOUND
        result = self.read_registry_result(key_path, value_name)
        return bool(result and result.state in (VALUE, NOT_FOUND)
                    and result.state != NOT_FOUND)

    def get_smb_signing(self):
        if self.smb:
            return self.smb.get_smb_signing()
        return 'UNKNOWN'

    def get_smb_version(self):
        if self.smb:
            return self.smb.get_smb_version()
        return 'UNKNOWN'

    def get_capabilities(self):
        capabilities = {
            'wmi': bool(getattr(self.wmi, 'connected', False)),
            'smb': bool(self.smb and self.smb.connected),
            'registry': bool(self.registry_ok),
            'registry_source': self.registry_source,
        }
        if hasattr(self.wmi, 'get_capabilities'):
            capabilities.update(self.wmi.get_capabilities())
        if self.smb and self.smb.registry_ok:
            capabilities['registry_source'] = 'ms-rrp'
            capabilities['registry'] = True
        return capabilities

    def execute(self, command):
        return None

    def close(self):
        if self.smb:
            try:
                self.smb.close()
            except Exception:
                pass
        if self.wmi:
            try:
                self.wmi.close()
            except Exception:
                pass
