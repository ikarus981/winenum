"""Kernel protection checks (OPSEC-safe, cross-platform)"""


class KernelCheck:
    """Check kernel protections via registry reads (no PowerShell)"""

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating kernel protections...")

        self.results['hvci'] = self._check_hvci()
        self.results['secure_boot'] = self._check_secure_boot()
        self.results['dep'] = self._check_dep()
        self.results['sehop'] = self._check_sehop()
        self.results['test_signing'] = self._check_test_signing()
        self.results['debug_mode'] = self._check_debug_mode()

        # Version-gated checks
        if self.os_target and self.os_target.supports_cet:
            self.results['cet'] = self._check_cet()

        if self.os_target and self.os_target.supports_kernel_shadow_stacks:
            self.results['kernel_shadow_stacks'] = self._check_kernel_shadow_stacks()

        return self.results

    def _check_hvci(self):
        """Check HVCI.

        Prefer WMI SecurityServicesRunning (service ID 2).  When WMI is
        unavailable, fall back to the registry Scenarios key -> CONFIGURED
        when set (may need a reboot to actually run)."""
        if self.os_target and not self.os_target.supports_hvci_wmi:
            return 'NOT SUPPORTED'
        if hasattr(self.transport, 'get_device_guard'):
            results = self.transport.get_device_guard()
            if results:
                for r in results:
                    if hasattr(r, 'SecurityServicesRunning'):
                        if 2 in r.SecurityServicesRunning:
                            return 'ENABLED'
                        return 'DISABLED'
        # No WMI -> registry fallback
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity',
                    'Enabled', 'NOT CONFIGURED')
        if v == 'NOT CONFIGURED':
            return 'NOT CONFIGURED'
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return 'CONFIGURED' if v == 1 else 'NOT CONFIGURED'

    def _check_secure_boot(self):
        """Check Secure Boot via registry (Win 8+/Server 2012+)."""
        from ..utils import reg_val
        value = reg_val(
            self.transport,
            r'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State',
            'UEFISecureBoot',
            'DISABLED',
        )
        if value == 'UNKNOWN':
            return 'UNKNOWN'
        if value == 'DISABLED' or value == 0:
            start_options = reg_val(
                self.transport,
                r'HKLM\SYSTEM\CurrentControlSet\Control',
                'SystemStartOptions',
                '',
            )
            if start_options != 'UNKNOWN' and 'TESTSIGNING' in str(start_options).upper():
                return 'DISABLED (Test Mode)'
            return 'DISABLED'
        return 'ENABLED' if value == 1 else 'UNKNOWN'

    def _check_dep(self):
        """Check DEP via registry (all Windows versions).

        DEP/NX is enabled by default on modern Windows; an absent
        'DisableNx' value means it has not been disabled -> enabled.
        """
        from ..utils import reg_val
        key = r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        val = reg_val(self.transport, key, 'DisableNx', 'ENABLED (by default)')
        if val in ('UNKNOWN', 'ENABLED (by default)'):
            return val
        return 'DISABLED' if val == 1 else 'ENABLED'

    def _check_sehop(self):
        """Check SEHOP via registry (Windows Server 2008 R2+, Windows 8+)"""
        from ..utils import reg_val
        key = r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
        val = reg_val(self.transport, key, 'DisableExceptionChainValidation',
                      'ENABLED (by default)')
        if val == 'UNKNOWN':
            return 'UNKNOWN'
        if val == 'ENABLED (by default)':
            return val
        return 'DISABLED' if val == 1 else 'ENABLED'

    def _check_test_signing(self):
        """Check Test Signing mode via registry."""
        from ..utils import reg_val
        value = reg_val(
            self.transport,
            r'HKLM\SYSTEM\CurrentControlSet\Control',
            'SystemStartOptions',
            '',
        )
        if value == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if 'TESTSIGNING' in str(value).upper() else 'DISABLED'

    def _check_debug_mode(self):
        """Check Debug mode via registry."""
        from ..utils import reg_val
        value = reg_val(
            self.transport,
            r'HKLM\SYSTEM\CurrentControlSet\Control',
            'SystemStartOptions',
            '',
        )
        if value == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if 'DEBUG' in str(value).upper() else 'DISABLED'

    def _check_cet(self):
        """Check CET / Shadow Stack (Win10 2004+).

        CETEnabled=1 means Hardware Shadow Stack is active.  A missing value
        means the feature simply is not enabled (real, not a guessed default).
        """
        from ..utils import reg_val
        key = r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
        val = reg_val(self.transport, key, 'CETEnabled', 'DISABLED')
        if val == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if val == 1 else 'DISABLED'

    def _check_kernel_shadow_stacks(self):
        """Check Kernel Data Protection shadow stacks (Win11+)."""
        from ..utils import reg_val
        key = r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        val = reg_val(self.transport, key, 'EnableKernelShadowStacks', 'DISABLED')
        if val == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if val == 1 else 'DISABLED'

    def display(self):
        self.console.section("KERNEL PROTECTIONS")

        hvci = self.results.get('hvci', 'UNKNOWN')
        if hvci == 'ENABLED':
            self.console.item("HVCI", hvci, 'ok')
        elif hvci == 'NOT SUPPORTED':
            self.console.item("HVCI", hvci)
        else:
            self.console.item("HVCI", hvci, 'warn')

        sb = self.results.get('secure_boot', 'UNKNOWN')
        if sb == 'ENABLED':
            self.console.item("Secure Boot", sb, 'ok')
        else:
            self.console.item("Secure Boot", sb, 'warn')

        dep = self.results.get('dep', 'UNKNOWN')
        if 'ENABLED' in str(dep):
            self.console.item("DEP/NX", dep, 'ok')
        else:
            self.console.item("DEP/NX", dep, 'warn')

        sehop = self.results.get('sehop', 'UNKNOWN')
        if 'ENABLED' in str(sehop):
            self.console.item("SEHOP", sehop, 'ok')
        else:
            self.console.item("SEHOP", sehop, 'warn')

        cet = self.results.get('cet')
        if cet:
            if cet == 'ENABLED':
                self.console.item("CET/Shadow Stack", cet, 'ok')
            else:
                self.console.item("CET/Shadow Stack", cet, 'warn')

        kds = self.results.get('kernel_shadow_stacks')
        if kds:
            if kds == 'ENABLED':
                self.console.item("Kernel Shadow Stacks", kds, 'ok')
            else:
                self.console.item("Kernel Shadow Stacks", kds, 'warn')

        ts = self.results.get('test_signing', 'UNKNOWN')
        if ts == 'ENABLED':
            self.console.item("Test Signing", ts, 'crit')
        else:
            self.console.item("Test Signing", ts, 'ok')

        dm = self.results.get('debug_mode', 'UNKNOWN')
        if dm == 'ENABLED':
            self.console.item("Debug Mode", dm, 'crit')
        else:
            self.console.item("Debug Mode", dm, 'ok')
