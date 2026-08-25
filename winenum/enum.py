"""Enumeration orchestration and risk assessment."""

from .utils.os_target import OSTarget


class WinEnum:
    """Run the available Windows security configuration checks."""

    def __init__(self, transport, console, target):
        self.transport = transport
        self.console = console
        self.target = target
        self.os_target = None
        self.all_results = {}

    def run_all(self):
        from .checks import (
            SystemCheck,
            LSACheck,
            KernelCheck,
            DefenderCheck,
            DriverCheck,
            LSAPackageCheck,
            PortCheck,
            NetworkCheck,
            KerberosCheck,
            LAPSCheck,
            SmartScreenCheck,
        )

        system_check = SystemCheck(self.transport, self.console)
        system_results = system_check.run()
        self.all_results['SystemCheck'] = system_results
        system_check.display()

        self.os_target = OSTarget(
            caption=system_results.get('os_version', ''),
            build_number=system_results.get('build_number', ''),
            version=system_results.get('version', ''),
            product_type=system_results.get('product_type'),
            domain_role=system_results.get('domain_role'),
            ubr=system_results.get('ubr'),
            product_name=system_results.get('product_name', ''),
        )
        self.all_results['TargetProfile'] = {
            'name': self.os_target.friendly_name,
            'build': self.os_target.build,
            'role': self.os_target.role_name,
            'server': self.os_target.is_server,
            'domain_controller': self.os_target.is_domain_controller,
            'ubr': self.os_target.ubr,
        }
        if hasattr(self.transport, 'get_capabilities'):
            self.all_results['Capabilities'] = self.transport.get_capabilities()
        self.console.info(
            f"Detected: {self.os_target.friendly_name} "
            f"(Build {self.os_target.build}; {self.os_target.role_name})"
        )

        checks = [
            PortCheck(self.transport, self.console, self.os_target),
            LSACheck(self.transport, self.console, self.os_target),
            KernelCheck(self.transport, self.console, self.os_target),
            DefenderCheck(self.transport, self.console, self.os_target),
            DriverCheck(self.transport, self.console, self.os_target),
            LSAPackageCheck(self.transport, self.console, self.os_target),
            NetworkCheck(self.transport, self.console, self.os_target),
            KerberosCheck(self.transport, self.console, self.os_target),
            LAPSCheck(self.transport, self.console, self.os_target),
            SmartScreenCheck(self.transport, self.console, self.os_target),
        ]

        for check in checks:
            try:
                results = check.run()
                self.all_results[check.__class__.__name__] = results
                check.display()
            except Exception as exc:
                self.console.error(f"Check failed: {exc}")

        return self.all_results

    @staticmethod
    def _is_unknown(value):
        return value in (None, '', 'UNKNOWN')

    def get_risk_assessment(self):
        """Return (level, message) using only explicit observations."""
        lsa = self.all_results.get('LSACheck', {})
        kernel = self.all_results.get('KernelCheck', {})
        defender = self.all_results.get('DefenderCheck', {})
        network = self.all_results.get('NetworkCheck', {})
        kerberos = self.all_results.get('KerberosCheck', {})
        laps = self.all_results.get('LAPSCheck', {})
        smartscreen = self.all_results.get('SmartScreenCheck', {})

        critical = 0
        warnings = 0
        good = 0
        unknown = 0

        def observe(value, positive=(), warning=(), critical_values=()):
            nonlocal critical, warnings, good, unknown
            if self._is_unknown(value) or value == 'NOT APPLICABLE':
                unknown += 1
            elif value in positive:
                good += 1
            elif value in critical_values:
                critical += 1
            elif value in warning:
                warnings += 1

        observe(lsa.get('ppl'), positive=('ENABLED', 'ENABLED (UEFI Lock)'),
                warning=('NOT CONFIGURED',))
        observe(lsa.get('credguard'), positive=('ENABLED',),
                warning=('CONFIGURED', 'NOT CONFIGURED'),
                critical_values=('DISABLED',))
        observe(kernel.get('hvci'), positive=('ENABLED',),
                warning=('DISABLED', 'CONFIGURED', 'NOT CONFIGURED'))
        observe(lsa.get('vbs'), positive=('ENABLED', 'RUNNING'),
                warning=('DISABLED', 'CONFIGURED', 'NOT CONFIGURED'))

        if self.os_target and self.os_target.supports_cet:
            observe(kernel.get('cet'), positive=('ENABLED',),
                    warning=('DISABLED', 'NOT CONFIGURED'))

        asr = defender.get('asr_rules', {})
        asr_status = asr.get('status')
        if asr_status == 'UNKNOWN':
            unknown += 1
        elif asr_status == 'NOT CONFIGURED':
            warnings += 1
        else:
            asr_enabled = len(asr.get('enabled', []))
            if asr_enabled > 5:
                good += 1
            else:
                warnings += 1

        observe(defender.get('realtime'), positive=('ENABLED',),
                warning=('ENABLED (by default)',),
                critical_values=('DISABLED',))
        observe(defender.get('tamper'), positive=('ENABLED',),
                warning=('DISABLED',))
        observe(defender.get('controlled_folder'), positive=('ENABLED',),
                warning=('DISABLED', 'DISABLED (by default)'))

        observe(network.get('smb_signing_required'), positive=('REQUIRED',),
                warning=('NOT REQUIRED',))
        observe(network.get('smb_v1_disabled'),
                positive=('DISABLED', 'DISABLED (not installed)'),
                critical_values=('ENABLED',))
        observe(network.get('smb_encryption'), positive=('ENABLED',),
                warning=('DISABLED', 'DISABLED (by default)'))
        observe(network.get('ldap_signing'), positive=('REQUIRED',),
                warning=('NEGOTIATE', 'NONE', 'NONE (by default)', 'NONE (0)'))
        observe(network.get('ldap_channel_binding'),
                positive=('ALWAYS', 'WHEN SUPPORTED'),
                warning=('DISABLED', 'WHEN SUPPORTED (by default)'))
        observe(network.get('netlogon_signing'), positive=('ENABLED',),
                warning=('DISABLED', 'ENABLED (by default)'))
        observe(network.get('netlogon_sealing'), positive=('ENABLED',),
                warning=('DISABLED',))
        observe(network.get('rdp_nla'), positive=('ENABLED',),
                warning=('DISABLED',))
        observe(network.get('ntlm_level'), positive=('NTLMv2 only',),
                warning=('Level 3 (by default)', 'Level 3 (Default)'),
                critical_values=())
        ntlm_level = network.get('ntlm_level', '')
        if not self._is_unknown(ntlm_level) and 'LM allowed' in str(ntlm_level):
            critical += 1
        observe(network.get('ntlm_restriction'), positive=('BLOCK ALL',),
                warning=('AUDIT', 'ALLOW ALL', 'ALLOW ALL (by default)'))

        etypes = kerberos.get('encryption_types')
        if isinstance(etypes, int):
            if etypes == 0x7FFFFFF8 or etypes & 0x18 == etypes:
                good += 1
            else:
                warnings += 1
        elif etypes != 'NOT APPLICABLE':
            unknown += 1
        observe(kerberos.get('rc4_rejected'), positive=('ENABLED',),
                warning=('DISABLED', 'DISABLED (by default)'))
        observe(kerberos.get('delegation_restricted'), positive=('DISABLED',),
                warning=('ENABLED (by default)',), critical_values=('ENABLED',))

        backup = laps.get('backup_directory')
        observe(backup, positive=('AD', 'AZURE AD', '1', '2'),
                warning=('NOT CONFIGURED',))
        password_length = laps.get('password_length')
        if self._is_unknown(password_length):
            unknown += 1
        elif password_length == 'NOT CONFIGURED':
            warnings += 1
        else:
            try:
                if int(password_length) >= 14:
                    good += 1
                else:
                    warnings += 1
            except (TypeError, ValueError):
                unknown += 1

        observe(smartscreen.get('smartscreen_desktop'), positive=('ENABLED',),
                warning=('DISABLED', 'ENABLED (by default)'))
        if self.os_target and self.os_target.supports_smart_app_control:
            observe(smartscreen.get('smart_app_control'),
                    positive=('ON', 'EVALUATION', 'ENFORCING'),
                    warning=('OFF', 'NOT CONFIGURED'))

        if critical >= 3:
            level = 'HIGH'
        elif critical >= 1 or warnings >= 4:
            level = 'MEDIUM'
        elif warnings >= 2:
            level = 'LOW'
        else:
            level = 'INFO'

        message = (
            f"{critical} critical, {warnings} warnings, "
            f"{good} protections confirmed, {unknown} unknown"
        )
        return level, message
