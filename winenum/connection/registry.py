"""Result types for remote registry reads."""

from dataclasses import dataclass


VALUE = 'VALUE'
NOT_FOUND = 'NOT_FOUND'
ACCESS_DENIED = 'ACCESS_DENIED'
UNAVAILABLE = 'UNAVAILABLE'
NOT_SUPPORTED = 'NOT_SUPPORTED'


@dataclass(frozen=True)
class RegistryResult:
    state: str
    value: object = None
    source: str = 'none'
    registry_type: int = None
    error: str = None

    @property
    def readable(self):
        return self.state in (VALUE, NOT_FOUND)


def value_result(value, source, registry_type=None):
    return RegistryResult(VALUE, value, source, registry_type)


def not_found_result(source):
    return RegistryResult(NOT_FOUND, source=source)


def unavailable_result(source='none', error=None, access_denied=False):
    state = ACCESS_DENIED if access_denied else UNAVAILABLE
    return RegistryResult(state, source=source, error=error)
