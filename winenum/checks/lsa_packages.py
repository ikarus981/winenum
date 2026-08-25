"""LSA authentication and security package checks."""


class LSAPackageCheck:
    """Read LSA package configuration without process or pipe enumeration."""

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating LSA package configuration...")

        self.results['auth_packages'] = self._get_auth_packages()
        self.results['security_packages'] = self._get_security_packages()

        return self.results

    def _get_auth_packages(self):
        """Get authentication packages via registry."""
        return self._get_package_value('Authentication Packages')

    def _get_security_packages(self):
        """Get security packages via registry."""
        return self._get_package_value('Security Packages')

    def _get_package_value(self, value_name):
        from ..utils import reg_val
        value = reg_val(
            self.transport,
            r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
            value_name,
            [],
        )
        if value in ('UNKNOWN', 'NOT CONFIGURED') or not value:
            return []
        if isinstance(value, bytes):
            items = value.decode('utf-16-le', errors='replace').split('\x00')
            return [item.strip() for item in items if item and item.strip()]
        if isinstance(value, (list, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).strip()
        if not text:
            return []
        return [p for p in text.split() if p.strip()]

    def display(self):
        auth = [p for p in (self.results.get('auth_packages', []) or []) if p and str(p).strip()]
        sec = [p for p in (self.results.get('security_packages', []) or []) if p and str(p).strip()]
        if not auth and not sec:
            return
        self.console.section("LSA PACKAGES")

        if auth:
            self.console.subsection("Authentication Packages")
            for pkg in auth:
                self.console.item(pkg, 'Loaded', 'ok')

        if sec:
            self.console.subsection("Security Packages")
            for pkg in sec:
                self.console.item(pkg, 'Loaded', 'ok')
