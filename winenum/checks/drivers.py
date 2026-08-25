"""Driver checks (OPSEC-safe via registry reads)"""


class DriverCheck:
    """Check vulnerable driver blocklist, WDAC, Smart App Control via registry"""

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating driver protections (registry reads)...")

        self.results['blocklist'] = self._check_blocklist()
        self.results['wdac'] = self._check_wdac()

        if self.os_target and self.os_target.supports_smart_app_control:
            self.results['smart_app_control'] = self._check_sac()

        return self.results

    def _check_blocklist(self):
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config',
                    'VulnerableDriverBlocklistEnable', 'UNKNOWN')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_wdac(self):
        """Check WDAC enforcement via VerifiedAndReputablePolicyState.

        Values: 0=Disabled, 1=Audit, 2=Enforced.
        Note: the old code mapped 0 and 1 both to ENFORCING which was wrong.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\CI',
                    'VerifiedAndReputablePolicyState',
                    'DISABLED (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'DISABLED (by default)':
            return v
        if v == 2:
            return 'ENFORCED'
        elif v == 1:
            return 'AUDIT'
        elif v == 0:
            return 'DISABLED'
        return f'CONFIGURED ({v})'

    def _check_sac(self):
        """Check Smart App Control (Win11 21H2+).

        Uses the correct path: SmartAppControlState under CI\\Config.
        Values: 1=On, 2=Evaluation, 3=Off.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config',
                    'SmartAppControlState', 'NOT CONFIGURED')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            # fallback: older WDAC policy state
            fallback = reg_val(
                self.transport,
                r'HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy',
                'VerifiedAndReputablePolicyState',
                'NOT CONFIGURED',
            )
            if fallback == 'UNKNOWN':
                return 'UNKNOWN'
            if fallback == 1:
                return 'ENFORCING'
            if v == 'UNKNOWN' and fallback == 'NOT CONFIGURED':
                return 'NOT CONFIGURED'
            return 'NOT CONFIGURED'
        if v == 1:
            return 'ON'
        elif v == 2:
            return 'EVALUATION'
        elif v == 3:
            return 'OFF'
        return f'CONFIGURED ({v})'

    def display(self):
        self.console.section("DRIVER PROTECTIONS")

        bl = self.results.get('blocklist', 'UNKNOWN')
        if bl == 'ENABLED':
            self.console.item("Vuln Driver Blocklist", bl, 'ok')
        elif bl == 'DISABLED':
            self.console.item("Vuln Driver Blocklist", bl, 'warn')
        else:
            self.console.item("Vuln Driver Blocklist", bl)

        wdac = self.results.get('wdac', 'UNKNOWN')
        if wdac == 'ENFORCED':
            self.console.item("WDAC", wdac, 'ok')
        elif wdac == 'AUDIT':
            self.console.item("WDAC", wdac, 'warn')
        else:
            self.console.item("WDAC", wdac, 'warn')

        sac = self.results.get('smart_app_control')
        if sac:
            if sac in ('ON', 'EVALUATION'):
                self.console.item("Smart App Control", sac, 'ok')
            else:
                self.console.item("Smart App Control", sac, 'warn')
