"""SmartScreen and Smart App Control checks"""


class SmartScreenCheck:
    """Check SmartScreen (Win10/11) and Smart App Control (Win11+)"""

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating SmartScreen / Smart App Control...")

        self.results['smartscreen_desktop'] = self._check_desktop_smartscreen()
        self.results['smartscreen_edge'] = self._check_edge_smartscreen()

        if self.os_target and self.os_target.supports_smart_app_control:
            self.results['smart_app_control'] = self._check_sac()

        return self.results

    def _check_desktop_smartscreen(self):
        """SmartScreen for desktop apps.

        Policy path (authoritative): EnableSmartScreen
        1=enabled, 0=disabled.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
                    'EnableSmartScreen', 'ENABLED (by default)')
        if v == 'UNKNOWN':
            # per-user / explorer path fallback
            v = reg_val(self.transport,
                        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
                        'SmartScreenEnabled', 'UNKNOWN')
            if v != 'UNKNOWN' and v != 'ENABLED (by default)':
                val_str = str(v).lower()
                return 'ENABLED' if val_str in ('1', 'warn', 'prompt') else 'DISABLED'
            return v
        if v == 'ENABLED (by default)':
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_edge_smartscreen(self):
        """Microsoft Edge SmartScreen.

        Path: HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\SmartScreenEnabled
        1=enabled, 0=disabled.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Policies\Microsoft\Edge',
                    'SmartScreenEnabled', 'ENABLED (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'ENABLED (by default)':
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_sac(self):
        """Smart App Control (Win11 21H2+).

        SmartAppControlState: 1=On, 2=Evaluation, 3=Off.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config',
                    'SmartAppControlState', 'NOT CONFIGURED')
        if v == 'UNKNOWN':
            # fallback: older WDAC policy state
            v = reg_val(self.transport,
                        r'HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy',
                        'VerifiedAndReputablePolicyState', 'UNKNOWN')
            if v == 'UNKNOWN':
                return 'UNKNOWN'
            return 'ENFORCING' if v == 1 else 'NOT CONFIGURED'
        if v == 1:
            return 'ON'
        elif v == 2:
            return 'EVALUATION'
        elif v == 3:
            return 'OFF'
        return f'CONFIGURED ({v})'

    def display(self):
        self.console.section("SMARTSCREEN / SMART APP CONTROL")

        desktop = self.results.get('smartscreen_desktop', 'UNKNOWN')
        if desktop == 'ENABLED':
            self.console.item("Desktop SmartScreen", desktop, 'ok')
        elif desktop == 'DISABLED':
            self.console.item("Desktop SmartScreen", desktop, 'warn')
        else:
            self.console.item("Desktop SmartScreen", desktop)

        edge = self.results.get('smartscreen_edge', 'UNKNOWN')
        if edge == 'ENABLED':
            self.console.item("Edge SmartScreen", edge, 'ok')
        elif edge == 'DISABLED':
            self.console.item("Edge SmartScreen", edge, 'warn')
        else:
            self.console.item("Edge SmartScreen", edge)

        sac = self.results.get('smart_app_control')
        if sac:
            if sac in ('ON', 'EVALUATION', 'ENFORCING'):
                self.console.item("Smart App Control", sac, 'ok')
            else:
                self.console.item("Smart App Control", sac, 'warn')
