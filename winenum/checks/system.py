"""System identity and operating system checks."""


class SystemCheck:
    """Collect target identity from WMI and registry evidence."""

    OS_REGISTRY_PATH = r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    COMPUTER_NAME_PATH = (
        r'HKLM\SYSTEM\CurrentControlSet\Control\ComputerName'
        r'\ActiveComputerName'
    )
    PRODUCT_OPTIONS_PATH = r'HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions'

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}
        self._os = None
        self._computer = None

    def run(self):
        self.console.info("Gathering system information...")
        self._os = self._first(self._query('get_operating_system'))
        self._computer = self._first(self._query('get_computer_system'))

        self.results['computer_name'] = self._get_computer_name()
        self.results['domain'] = self._get_domain()
        self.results['architecture'] = self._get_architecture()
        self.results['build_number'] = self._get_build_number()
        self.results['version'] = self._get_version_string()
        self.results['product_type'] = self._get_product_type()
        self.results['domain_role'] = self._get_domain_role()
        self.results['part_of_domain'] = self._get_part_of_domain()
        self.results['product_name'] = self._get_registry('ProductName')
        self.results['edition'] = self._get_registry('EditionID')
        self.results['install_type'] = self._get_registry('InstallationType')
        self.results['ubr'] = self._get_registry('UBR')
        self.results['os_version'] = self._get_os_version()
        self.results['identity_source'] = self._identity_source()
        return self.results

    def _query(self, method):
        if not hasattr(self.transport, method):
            return []
        try:
            return getattr(self.transport, method)() or []
        except Exception as exc:
            self.console.debug_msg(f"System query failed ({method}): {exc}")
            return []

    @staticmethod
    def _first(results):
        return (results or [None])[0]

    def _get_registry(self, name):
        from ..utils import reg_val
        return reg_val(self.transport, self.OS_REGISTRY_PATH, name, None)

    def _get_computer_name(self):
        value = getattr(self._computer, 'Name', None)
        if value:
            return value
        value = self._get_registry_path(self.COMPUTER_NAME_PATH, 'ComputerName')
        return value if value not in (None, 'UNKNOWN') else 'UNKNOWN'

    def _get_registry_path(self, key_path, name):
        from ..utils import reg_val
        return reg_val(self.transport, key_path, name, None)

    def _get_domain(self):
        value = getattr(self._computer, 'Domain', None)
        if value:
            return value
        for key_path, value_name in (
            (r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'Domain'),
            (r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'NV Domain'),
        ):
            reg_value = self._get_registry_path(key_path, value_name)
            if reg_value not in (None, 'UNKNOWN', ''):
                return str(reg_value)
        return 'UNKNOWN'

    def _get_os_version(self):
        caption = getattr(self._os, 'Caption', None)
        build = self.results.get('build_number')
        if caption:
            return f'{caption} (Build {build})' if build else caption
        product_name = self.results.get('product_name')
        if product_name not in (None, 'UNKNOWN'):
            return f'{product_name} (Build {build})' if build else product_name
        return 'UNKNOWN'

    def _get_architecture(self):
        value = getattr(self._os, 'OSArchitecture', None)
        if value:
            return value
        raw = self._get_registry('BuildBranch')
        if raw not in (None, 'UNKNOWN', ''):
            return '64 bits' if 'amd64' in str(raw).lower() or 'x64' in str(raw).lower() else 'UNKNOWN'
        arch_raw = self._get_registry_path(r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'PROCESSOR_ARCHITECTURE')
        if arch_raw not in (None, 'UNKNOWN', ''):
            mapping = {'AMD64': '64 bits', 'EM64T': '64 bits', 'IA64': '64 bits', 'x86': '32 bits'}
            return mapping.get(str(arch_raw).upper(), str(arch_raw))
        return 'UNKNOWN'

    def _get_build_number(self):
        value = getattr(self._os, 'BuildNumber', None)
        if value:
            return str(value)
        for name in ('CurrentBuildNumber', 'CurrentBuild'):
            value = self._get_registry(name)
            if value not in (None, 'UNKNOWN'):
                return str(value)
        return ''

    def _get_version_string(self):
        value = getattr(self._os, 'Version', None)
        if value:
            return str(value)
        current_version = self._get_registry('CurrentVersion')
        return str(current_version) if current_version not in (None, 'UNKNOWN') else ''

    def _get_product_type(self):
        value = getattr(self._os, 'ProductType', None)
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            pass
        raw = self._get_registry_path(self.PRODUCT_OPTIONS_PATH, 'ProductType')
        if isinstance(raw, str) and raw not in (None, 'UNKNOWN'):
            mapping = {'WinNT': 1, 'ServerNT': 3, 'LanmanNT': 2}
            return mapping.get(raw.strip(), None)
        return None

    def _get_domain_role(self):
        value = getattr(self._computer, 'DomainRole', None)
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            pass
        product_type = self.results.get('product_type')
        if product_type == 2:
            return 5
        if product_type in (1, 3):
            domain = self.results.get('domain')
            part = self.results.get('part_of_domain')
            if domain not in (None, 'UNKNOWN', '') and part:
                return 3
            return 2 if domain not in (None, 'UNKNOWN', '') else 0
        return None

    def _get_part_of_domain(self):
        value = getattr(self._computer, 'PartOfDomain', None)
        if value is not None:
            return bool(value)
        raw = self._get_registry_path(self.PRODUCT_OPTIONS_PATH, 'ProductType')
        if isinstance(raw, str) and raw not in (None, 'UNKNOWN'):
            return raw.strip() in ('ServerNT', 'LanmanNT')
        return None

    def _identity_source(self):
        if self._os or self._computer:
            return 'wmi'
        return 'registry' if self.results.get('product_name') not in (None, 'UNKNOWN') else 'none'

    def display(self):
        self.console.section("SYSTEM INFORMATION")
        self.console.item("Computer Name", self.results.get('computer_name', 'UNKNOWN'))
        self.console.item("Domain", self.results.get('domain', 'UNKNOWN'))
        self.console.item("OS Version", self.results.get('os_version', 'UNKNOWN'))
        self.console.item("Architecture", self.results.get('architecture', 'UNKNOWN'))
        self.console.item("Product", self.results.get('product_name', 'UNKNOWN'))
        self.console.item("Edition", self.results.get('edition', 'UNKNOWN'))
        self.console.item("Product Type", self.results.get('product_type', 'UNKNOWN'))
        self.console.item("Domain Role", self.results.get('domain_role', 'UNKNOWN'))
        self.console.item("Part of Domain", self.results.get('part_of_domain', 'UNKNOWN'))
