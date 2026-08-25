"""WMI and StdRegProv transport using DCOM."""

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.ndr import NULL

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


class WMITransport:
    """Query WMI classes and read the remote registry through StdRegProv."""

    REG_HIVES = {
        'HKCR': 0x80000000,
        'HKEY_CLASSES_ROOT': 0x80000000,
        'HKCU': 0x80000001,
        'HKEY_CURRENT_USER': 0x80000001,
        'HKLM': 0x80000002,
        'HKEY_LOCAL_MACHINE': 0x80000002,
        'HKU': 0x80000003,
        'HKEY_USERS': 0x80000003,
        'HKCC': 0x80000005,
        'HKEY_CURRENT_CONFIG': 0x80000005,
    }

    REGISTRY_METHODS = {
        1: ('GetStringValue', 'sValue'),
        2: ('GetExpandedStringValue', 'sValue'),
        3: ('GetBinaryValue', 'uValue'),
        4: ('GetDWORDValue', 'uValue'),
        7: ('GetMultiStringValue', 'sValue'),
        11: ('GetQWORDValue', 'uValue'),
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
        self.dcom = None
        self.iWbemLevel1Login = None
        self._services_cache = {}
        self._os_cache = None
        self._computer_cache = None
        self._device_guard_cache = None
        self._registry_provider = None
        self._registry_namespace = None
        self._registry_attempted = False
        self._registry_cache = {}
        self.registry_ok = False
        self.registry_source = 'none'
        self.last_registry_result = None

    def connect(self):
        try:
            self.dcom = DCOMConnection(
                self.target,
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                aesKey=self.aes_key,
                doKerberos=self.use_kerberos or bool(self.aes_key),
                kdcHost=self.dc_ip or None,
            )
            interface = self.dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login,
                wmi.IID_IWbemLevel1Login,
            )
            self.iWbemLevel1Login = wmi.IWbemLevel1Login(interface)
            self.connected = True
            return True
        except Exception as exc:
            if self.console:
                self.console.debug_msg(f"WMI DCOM connection failed: {exc}")
            self.close()
            return False

    def execute(self, command):
        return None

    def _get_services(self, namespace):
        ns_key = namespace.lower()
        if ns_key in self._services_cache:
            return self._services_cache[ns_key]
        if not self.iWbemLevel1Login:
            return None
        try:
            services = self.iWbemLevel1Login.NTLMLogin(
                '//./' + namespace.replace('\\', '/'),
                NULL,
                NULL,
            )
        except Exception as exc:
            if self.console:
                self.console.debug_msg(f"WMI login failed for {namespace}: {exc}")
            return None
        self._services_cache[ns_key] = services
        return services

    def wmi_query(self, wmi_class, properties=None, namespace='root\\cimv2'):
        """Execute a read-only WQL query through DCOM."""
        services = self._get_services(namespace)
        if services is None:
            return []
        props = ','.join(properties) if properties and properties != ['*'] else '*'
        query = f'SELECT {props} FROM {wmi_class}'
        try:
            enumerator = services.ExecQuery(query)
        except Exception as exc:
            if self.console:
                self.console.debug_msg(f"WMI query failed ({wmi_class}): {exc}")
            return []

        results = []
        while True:
            try:
                chunk = enumerator.Next(0xffffffff, 1)
            except wmi.DCERPCSessionError as exc:
                if getattr(exc, 'error_code', None) == wmi.WBEMSTATUS.WBEM_S_FALSE:
                    break
                if self.console:
                    self.console.debug_msg(f"WMI Next failed for {wmi_class}: {exc}")
                break
            except Exception as exc:
                if self.console:
                    self.console.debug_msg(f"WMI Next failed for {wmi_class}: {exc}")
                break
            if not chunk:
                break
            results.extend(chunk)
        return results

    def get_device_guard(self):
        """Get live DeviceGuard status through WMI."""
        if self._device_guard_cache is None:
            self._device_guard_cache = self.wmi_query(
                'Win32_DeviceGuard',
                [
                    'SecurityServicesRunning',
                    'SecurityServicesConfigured',
                    'VirtualizationBasedSecurityStatus',
                ],
                'root\\Microsoft\\Windows\\DeviceGuard',
            )
        return self._device_guard_cache

    def get_operating_system(self):
        """Get OS identity, build, edition, and product type through WMI."""
        if self._os_cache is None:
            self._os_cache = self.wmi_query(
                'Win32_OperatingSystem',
                [
                    'Caption',
                    'BuildNumber',
                    'OSArchitecture',
                    'Version',
                    'ProductType',
                    'InstallDate',
                ],
            )
        return self._os_cache

    def get_computer_system(self):
        """Get computer identity, membership, and domain role through WMI."""
        if self._computer_cache is None:
            self._computer_cache = self.wmi_query(
                'Win32_ComputerSystem',
                ['Name', 'Domain', 'UserName', 'PartOfDomain', 'DomainRole'],
            )
        return self._computer_cache

    @staticmethod
    def _registry_path(key_path):
        parts = key_path.split('\\', 1)
        if len(parts) != 2:
            return None, None
        hive = parts[0].upper()
        subkey = parts[1]
        if hive not in WMITransport.REG_HIVES or not subkey:
            return None, None
        return WMITransport.REG_HIVES[hive], subkey

    @staticmethod
    def _return_code(response):
        try:
            return int(getattr(response, 'ReturnValue'))
        except (AttributeError, TypeError, ValueError):
            return None

    @staticmethod
    def _error_is_access_denied(error):
        text = str(error).upper()
        return 'ACCESS_DENIED' in text or '0X5' in text

    def _get_registry_provider(self):
        if self._registry_provider is not None:
            return self._registry_provider
        if self._registry_attempted:
            return None

        self._registry_attempted = True
        for namespace in ('root\\default', 'root\\cimv2'):
            services = self._get_services(namespace)
            if services is None:
                continue
            try:
                provider, _ = services.GetObject('StdRegProv')
                self._registry_provider = provider
                self._registry_namespace = namespace
                self.registry_ok = True
                self.registry_source = 'stdregprov'
                return provider
            except Exception as exc:
                if self.console:
                    self.console.debug_msg(
                        f"StdRegProv unavailable in {namespace}: {exc}")

        self.registry_ok = False
        self.registry_source = 'none'
        return None

    def _status_result(self, response, source='stdregprov'):
        code = self._return_code(response)
        if code == 0:
            return RegistryResult(VALUE, source=source)
        if code in (2, 3):
            return not_found_result(source)
        return unavailable_result(source, error=f'ReturnValue={code}',
                                  access_denied=code == 5)

    def read_registry_result(self, key_path, value_name):
        """Read one registry value and retain source/error evidence."""
        cache_key = (key_path, value_name)
        if cache_key in self._registry_cache:
            return self._registry_cache[cache_key]

        hive, subkey = self._registry_path(key_path)
        if hive is None:
            result = unavailable_result(error='unsupported registry path')
            self._registry_cache[cache_key] = result
            return result

        provider = self._get_registry_provider()
        if provider is None:
            result = unavailable_result(error='StdRegProv unavailable')
            self._registry_cache[cache_key] = result
            return result

        try:
            enum_response = provider.EnumValues(hive, subkey)
        except Exception as exc:
            result = unavailable_result(
                'stdregprov',
                error=str(exc),
                access_denied=self._error_is_access_denied(exc),
            )
            self._registry_cache[cache_key] = result
            return result

        enum_status = self._status_result(enum_response)
        if enum_status.state != VALUE:
            self._registry_cache[cache_key] = enum_status
            return enum_status

        names = list(getattr(enum_response, 'sNames', None) or [])
        types = list(getattr(enum_response, 'Types', None) or [])
        value_type = None
        for index, name in enumerate(names):
            if str(name) == value_name:
                if index < len(types):
                    try:
                        value_type = int(types[index])
                    except (TypeError, ValueError):
                        value_type = None
                break

        if value_type is None:
            result = not_found_result('stdregprov')
            self._registry_cache[cache_key] = result
            return result

        method_info = self.REGISTRY_METHODS.get(value_type)
        if method_info is None:
            result = unavailable_result(
                'stdregprov',
                error=f'unsupported registry type {value_type}',
            )
            self._registry_cache[cache_key] = result
            return result

        method_name, output_name = method_info
        try:
            response = getattr(provider, method_name)(hive, subkey, value_name)
        except Exception as exc:
            result = unavailable_result(
                'stdregprov',
                error=str(exc),
                access_denied=self._error_is_access_denied(exc),
            )
            self._registry_cache[cache_key] = result
            return result

        status = self._status_result(response)
        if status.state != VALUE:
            self._registry_cache[cache_key] = status
            return status

        value = getattr(response, output_name, None)
        if value_type == 3 and value is not None:
            value = bytes(value)
        elif value_type == 7 and value is not None:
            value = list(value)
        result = value_result(value, 'stdregprov', value_type)
        self._registry_cache[cache_key] = result
        return result

    def get_registry_value(self, key_path, value_name):
        """Return a value, REG_NOT_FOUND, or None for an unavailable source."""
        from ..utils import REG_NOT_FOUND
        result = self.read_registry_result(key_path, value_name)
        if result.state == VALUE:
            return result.value
        if result.state == NOT_FOUND:
            return REG_NOT_FOUND
        return None

    def key_exists(self, key_path):
        hive, subkey = self._registry_path(key_path)
        provider = self._get_registry_provider()
        if hive is None or provider is None:
            return False
        try:
            response = provider.EnumValues(hive, subkey)
            return self._return_code(response) == 0
        except Exception:
            return False

    def value_exists(self, key_path, value_name):
        from ..utils import REG_NOT_FOUND
        value = self.get_registry_value(key_path, value_name)
        return value is not None and value is not REG_NOT_FOUND

    def get_capabilities(self):
        return {
            'wmi': bool(self.connected),
            'registry': bool(self.registry_ok),
            'registry_source': self.registry_source,
            'registry_namespace': self._registry_namespace,
        }

    def close(self):
        if self._registry_provider:
            try:
                self._registry_provider.RemRelease()
            except Exception:
                pass
        if self.iWbemLevel1Login:
            try:
                self.iWbemLevel1Login.RemRelease()
            except Exception:
                pass
        if self.dcom:
            try:
                self.dcom.disconnect()
            except Exception:
                pass
        self.connected = False
        self.registry_ok = False
        self.registry_source = 'none'
        self.last_registry_result = None
        self._registry_provider = None
        self._registry_namespace = None
        self._registry_attempted = False
        self._registry_cache = {}
        self._services_cache = {}
        self._os_cache = None
        self._computer_cache = None
        self._device_guard_cache = None
        self.dcom = None
        self.iWbemLevel1Login = None
