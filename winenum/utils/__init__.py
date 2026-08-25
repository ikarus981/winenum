"""Shared helpers for winenum."""

import re

from .os_target import OSTarget

REG_NOT_FOUND = object()


def can_read_registry(transport):
    """Return whether a registry backend is available or can be probed."""
    if transport is None:
        return False
    if getattr(transport, 'registry_ok', False):
        return True

    smb = getattr(transport, 'smb', None)
    if smb and getattr(smb, 'registry_ok', False):
        return True

    wmi = getattr(transport, 'wmi', transport)
    if getattr(wmi, 'connected', False):
        return True
    return hasattr(transport, 'read_registry_result')


def reg_val(transport, key_path, value_name, default_for_not_found='NOT CONFIGURED'):
    """Read a registry value using the transport's best backend."""
    if hasattr(transport, 'read_registry_result'):
        try:
            result = transport.read_registry_result(key_path, value_name)
        except Exception:
            return 'UNKNOWN'
        from ..connection.registry import NOT_FOUND, VALUE
        if result is None:
            return 'UNKNOWN'
        if result.state == VALUE:
            return result.value
        if result.state == NOT_FOUND:
            return default_for_not_found
        return 'UNKNOWN'

    if not hasattr(transport, 'get_registry_value'):
        return 'UNKNOWN'
    try:
        value = transport.get_registry_value(key_path, value_name)
    except Exception:
        return 'UNKNOWN'
    if value is REG_NOT_FOUND:
        return default_for_not_found
    if value is None:
        return 'UNKNOWN'
    return value


def parse_target(target):
    """Parse [domain/]username[:password]@host."""
    pattern = r'(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)'
    match = re.match(pattern, target)
    if not match:
        return None, None, None, target

    domain, username, password, host = match.groups()
    if '@' in host and password:
        password = password + '@' + host.rpartition('@')[0]
        host = host.rpartition('@')[2]
    return domain or '', username or '', password or '', host


def parse_hashes(hashes):
    """Parse LMHASH:NTHASH or a standalone NT hash."""
    if not hashes:
        return '', ''
    if ':' not in hashes:
        return '', hashes
    return hashes.split(':', 1)


def _json_safe(value):
    """Convert result values to JSON-compatible primitives."""
    if value is REG_NOT_FOUND:
        return 'NOT CONFIGURED'
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if hasattr(value, 'SecurityServicesRunning'):
        return {
            'security_services_running': _json_safe(
                list(value.SecurityServicesRunning)
            )
        }
    if hasattr(value, 'VirtualizationBasedSecurityStatus'):
        return {
            'vbs_status': _json_safe(value.VirtualizationBasedSecurityStatus)
        }
    if hasattr(value, 'Caption'):
        return {
            'caption': getattr(value, 'Caption', None),
            'build': getattr(value, 'BuildNumber', None),
            'os_architecture': getattr(value, 'OSArchitecture', None),
            'version': getattr(value, 'Version', None),
        }
    if hasattr(value, 'Name'):
        return {
            'name': getattr(value, 'Name', None),
            'domain': getattr(value, 'Domain', None),
        }
    return str(value)


def process_results_for_json(all_results, **metadata):
    """Build a JSON-serializable report."""
    payload = {
        'tool': 'winenum',
        'results': _json_safe(all_results),
    }
    payload.update({key: _json_safe(value) for key, value in metadata.items()})
    return payload
