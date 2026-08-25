"""LSA Protection checks (OPSEC-safe, cross-platform)"""


class LSACheck:
    """Check LSA protections via MS-RPC and registry (no PowerShell)"""

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating LSA protections...")

        self.results['ppl'] = self._check_ppl()
        self.results['ppl_boot'] = self._check_ppl_boot()
        self.results['credguard'] = self._check_credential_guard()
        self.results['credguard_lock'] = self._check_credential_guard_lock()
        self.results['vbs'] = self._check_vbs()
        self.results['lsa_config_flags'] = self._check_lsa_config()

        if self.os_target and self.os_target.supports_ppl_mode:
            self.results['ppl_mode'] = self._check_ppl_mode()

        return self.results

    def _registry_value(self, key_path, value_name):
        from ..connection.registry import NOT_FOUND, VALUE
        from ..utils import REG_NOT_FOUND
        if hasattr(self.transport, 'read_registry_result'):
            result = self.transport.read_registry_result(key_path, value_name)
            if result is None or result.state not in (VALUE, NOT_FOUND):
                return None, False
            if result.state == NOT_FOUND:
                return None, True
            return result.value, True

        value = self.transport.get_registry_value(key_path, value_name)
        if value is REG_NOT_FOUND:
            return None, True
        return value, value is not None

    def _check_ppl(self):
        """Check RunAsPPL using the policy and legacy registry locations."""
        value, readable = self._registry_value(
            r'HKLM\Software\Policies\Microsoft\Windows\System',
            'ConfigureLsaProtectedProcess'
        ) if self.os_target and self.os_target.supports_ppl_new_path else (None, True)
        if not readable:
            return 'UNKNOWN'
        if value is not None:
            if value == 1:
                return 'ENABLED'
            if value == 2:
                return 'ENABLED (UEFI Lock)'
            return f'CONFIGURED ({value})'

        value, _ = self._registry_value(
            r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
            'RunAsPPL'
        )
        if value is not None:
            if value == 1:
                return 'ENABLED'
            if value == 2:
                return 'ENABLED (UEFI Lock)'
            return f'CONFIGURED ({value})'
        return 'NOT CONFIGURED'

    def _check_ppl_boot(self):
        """Check RunAsPPLBoot UEFI lock state for PPL at boot."""
        value, readable = self._registry_value(
            r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
            'RunAsPPLBoot'
        )
        if not readable:
            return 'UNKNOWN'
        if value is None or value == 0:
            return 'NOT CONFIGURED'
        return 'ENABLED (UEFI Lock)' if value == 1 else f'CONFIGURED ({value})'

    def _check_ppl_mode(self):
        """Check RunAsPPLMode (Server 2025 / Win11 24H2)."""
        value, readable = self._registry_value(
            r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
            'RunAsPPLMode'
        )
        if not readable:
            return 'UNKNOWN'
        if value is None:
            return 'NOT CONFIGURED'
        if value == 1:
            return 'STRICT'
        if value == 2:
            return 'DYNAMIC'
        return f'CONFIGURED ({value})'


    def _check_credential_guard(self):
        """Check Credential Guard.

        Prefer WMI SecurityServicesRunning (service ID 1) for a live ENABLED.
        When WMI is unavailable, fall back to the registry Scenarios key:
        'Enabled'=1 means CredGuard is CONFIGURED (may require a reboot to be
        running) -> reported as CONFIGURED, never a guessed DISABLED.
        """
        if hasattr(self.transport, 'get_device_guard'):
            results = self.transport.get_device_guard()
            if results:
                for r in results:
                    if hasattr(r, 'SecurityServicesRunning'):
                        services = r.SecurityServicesRunning
                        if 1 in services:
                            return 'ENABLED'
                        return 'DISABLED'
        # No WMI -> registry fallback
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard',
                    'Enabled', 'NOT CONFIGURED')
        if v == 'NOT CONFIGURED':
            return 'NOT CONFIGURED'
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return 'CONFIGURED' if v == 1 else 'NOT CONFIGURED'

    def _check_credential_guard_lock(self):
        """Check if Credential Guard has a UEFI lock."""
        value, readable = self._registry_value(
            r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
            'Locked'
        )
        if not readable:
            return 'UNKNOWN'
        if value is None:
            return 'NOT CONFIGURED'
        return 'LOCKED' if value == 1 else 'NOT LOCKED'

    def _check_vbs(self):
        """Check VBS.

        Prefer WMI VirtualizationBasedSecurityStatus for live status.  When
        WMI is unavailable, fall back to the EnableVirtualizationBasedSecurity
        registry value -> CONFIGURED when set.
        """
        if hasattr(self.transport, 'get_device_guard'):
            results = self.transport.get_device_guard()
            if results:
                for r in results:
                    if hasattr(r, 'VirtualizationBasedSecurityStatus'):
                        status = r.VirtualizationBasedSecurityStatus
                        if status == 0:
                            return 'DISABLED'
                        elif status == 1:
                            return 'ENABLED'
                        elif status == 2:
                            return 'RUNNING'
        # No WMI -> registry fallback
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
                    'EnableVirtualizationBasedSecurity', 'NOT CONFIGURED')
        if v == 'NOT CONFIGURED':
            return 'NOT CONFIGURED'
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return 'CONFIGURED' if v == 1 else 'NOT CONFIGURED'

    def _check_lsa_config(self):
        """Check LsaCfgFlags across local and policy locations."""
        locations = (
            r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
            r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
            r'HKLM\Software\Policies\Microsoft\Windows\System',
        )
        for key_path in locations:
            value, readable = self._registry_value(key_path, 'LsaCfgFlags')
            if not readable:
                return 'UNKNOWN'
            if value is not None:
                return str(value)
        return 'NOT CONFIGURED'

    def display(self):
        self.console.section("LSA PROTECTIONS")

        ppl = self.results.get('ppl', 'UNKNOWN')
        if 'ENABLED' in ppl:
            self.console.item("PPL (RunAsPPL)", ppl, 'ok')
        elif 'NOT CONFIGURED' in ppl:
            self.console.item("PPL (RunAsPPL)", ppl, 'crit')
        else:
            self.console.item("PPL (RunAsPPL)", ppl, 'warn')

        ppl_boot = self.results.get('ppl_boot')
        if ppl_boot:
            if 'UEFI Lock' in str(ppl_boot):
                self.console.item("PPL Boot Lock", ppl_boot, 'ok')
            else:
                self.console.item("PPL Boot Lock", ppl_boot, 'warn')

        ppl_mode = self.results.get('ppl_mode')
        if ppl_mode:
            if ppl_mode == 'STRICT':
                self.console.item("PPL Mode", ppl_mode, 'ok')
            elif ppl_mode == 'DYNAMIC':
                self.console.item("PPL Mode", ppl_mode, 'warn')
            else:
                self.console.item("PPL Mode", ppl_mode)

        cg = self.results.get('credguard', 'UNKNOWN')
        if cg == 'ENABLED':
            self.console.item("Credential Guard", cg, 'ok')
        elif cg == 'DISABLED':
            self.console.item("Credential Guard", cg, 'crit')
        else:
            self.console.item("Credential Guard", cg, 'warn')

        cg_lock = self.results.get('credguard_lock')
        if cg_lock:
            if cg_lock == 'LOCKED':
                self.console.item("CredGuard UEFI Lock", cg_lock, 'ok')
            else:
                self.console.item("CredGuard UEFI Lock", cg_lock, 'warn')

        vbs = self.results.get('vbs', 'UNKNOWN')
        if vbs in ('ENABLED', 'RUNNING'):
            self.console.item("VBS Status", vbs, 'ok')
        elif vbs == 'DISABLED':
            self.console.item("VBS Status", vbs, 'warn')
        else:
            self.console.item("VBS Status", vbs)

        self.console.item("LSA Config Flags", self.results.get('lsa_config_flags', 'UNKNOWN'))
