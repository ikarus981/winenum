"""Windows Defender checks (OPSEC-safe, cross-platform)"""


class DefenderCheck:
    """Check Windows Defender via registry (no PowerShell cmdlets)"""

    ASR_RULES = {
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2': ('Block credential stealing from lsass', '1803+'),
        '56a863a9-875e-4185-98a7-b882c64b5ce5': ('Block Office applications from injecting code', '1709+'),
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': ('Block Office applications from creating child processes', '1709+'),
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a': ('Block Office applications from creating executable content', '1709+'),
        '3b576869-ab4b-4d18-b1d4-437115f577ac': ('Block Office child processes', '1709+'),
        'd1e49aac-8f56-4280-b9ba-993a6d77406c': ('Block process creations from PSExec/WMI', '1803+'),
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': ('Block Win32 API calls from Office macros', '1709+'),
        '01443614-cd74-433a-b99e-2ecdc07bfc25': ('Block all Office applications from creating child processes', '1709+'),
        'e6db77e5-3df2-4cf1-b95a-636979351e5b': ('Block persistence through WMI event subscription', '1903+'),
        'c2638844-1009-4ad5-a85c-6454abde0247': ('Block Office communication apps from creating child processes', '1709+'),
        '26190899-1602-49e8-8b27-eb1d0a1ce869': ('Block Office applications from creating child processes', '1709+'),
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc': ('Block executable content from email client and webmail', '1709+'),
        '92e97fa1-2edf-4476-bdd6-9dd0b4e364c2': ('Block JavaScript/VBScript from launching downloaded content', '1709+'),
        '9ece6d59-3b6e-4b55-865f-314cf1fc4c30': ('Block executable files from running unless', '1803+'),
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': ('Block untrusted and unsigned processes from USB', '1709+'),
        'c1db55ab-c21a-4637-bb3f-a12568109d35': ('Block untrusted and unsigned processes from USB', '1709+'),
        'c3c85054-0f9f-4f51-a4cf-5c6c45d1884e': ('Block Office apps from creating child processes', '1709+'),
        '5dd5a97e-9a24-4920-a2a5-7e9f6269c344': ('Block Office apps from creating child processes', '1709+'),
        '4c947366-5293-4df5-8a0a-46e7e1a2237d': ('Block Office apps from creating child processes', '1709+'),
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': ('Block executable content from email', '1709+'),
        '33ddedf1-c6e0-47cb-833e-de6133960387': ('Block executable content from email', '1709+'),
    }

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating Windows Defender (registry reads)...")

        self.results['realtime'] = self._check_realtime()
        self.results['tamper'] = self._check_tamper()
        self.results['cloud'] = self._check_cloud()
        self.results['behavior'] = self._check_behavior()
        self.results['signature_ver'] = self._check_signature()
        self.results['asr_rules'] = self._check_asr_rules()

        if self.os_target and self.os_target.supports_controlled_folder_access:
            self.results['controlled_folder'] = self._check_controlled_folder()

        return self.results

    def _check_realtime(self):
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
                    'DisableRealtimeMonitoring', 'ENABLED (by default)')
        if v == 'UNKNOWN' or v == 'ENABLED (by default)':
            return v
        return 'DISABLED' if v == 1 else 'ENABLED'

    def _check_tamper(self):
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Microsoft\Windows Defender\Features',
                    'TamperProtection', 'UNKNOWN')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if v >= 1 else 'DISABLED'

    def _check_cloud(self):
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet',
                    'MAPSReporting', 'DISABLED (by default)')
        if v == 'UNKNOWN' or v == 'DISABLED (by default)':
            return v
        if v == 0:
            return 'DISABLED'
        elif v == 1:
            return 'ENABLED (Basic)'
        elif v == 2:
            return 'ENABLED (Advanced)'
        return f'CONFIGURED ({v})'

    def _check_behavior(self):
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
                    'DisableBehaviorMonitoring', 'ENABLED (by default)')
        if v == 'UNKNOWN' or v == 'ENABLED (by default)':
            return v
        return 'DISABLED' if v == 1 else 'ENABLED'

    def _check_signature(self):
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates',
                    'AVSignatureVersion', 'UNKNOWN')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return 'UNKNOWN'
        return str(v)

    def _check_controlled_folder(self):
        """Check Controlled Folder Access (Ransomware protection, Win10 1709+)."""
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Amsi',
                    'EnableControllerSetPolicy', 'DISABLED (by default)')
        if v == 'UNKNOWN':
            # alternate path
            v = reg_val(self.transport,
                        r'HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Amsi',
                        'EnableControllerSetPolicy', 'DISABLED (by default)')
        if v == 'UNKNOWN' or v == 'DISABLED (by default)':
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    ASR_POLICY_PATH = (r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
                       r'\Windows Defender Exploit Guard\ASR')

    def _check_asr_rules(self):
        """Read ASR state via GPO policy values (REG_MULTI_SZ Ids/Actions)."""
        from ..utils import reg_val
        enabled = []
        disabled = []

        ids = reg_val(self.transport, self.ASR_POLICY_PATH,
                      'AttackSurfaceReductionRules_Ids', 'NOT CONFIGURED')
        if ids in ('UNKNOWN', 'NOT CONFIGURED'):
            return {'enabled': [], 'disabled': [], 'status': ids}

        actions = reg_val(self.transport, self.ASR_POLICY_PATH,
                          'AttackSurfaceReductionRules_Actions', [])
        if actions == 'UNKNOWN':
            return {'enabled': [], 'disabled': [], 'status': 'UNKNOWN'}
        if isinstance(ids, str):
            ids = [ids]
        if isinstance(actions, str):
            actions = [actions]

        for i, guid in enumerate(ids):
            guid = guid.strip().lower()
            name, min_ver = self.ASR_RULES.get(
                guid, (f'Custom rule {guid}', ''))
            action = actions[i].strip() if i < len(actions) else '1'
            if action == '1':
                enabled.append((name, guid, 'Block', min_ver))
            elif action == '2':
                enabled.append((name, guid, 'Audit', min_ver))
            else:
                disabled.append((name, guid, min_ver))

        return {'enabled': enabled, 'disabled': disabled}

    def display(self):
        self.console.section("WINDOWS DEFENDER")

        rt = self.results.get('realtime', 'UNKNOWN')
        if rt == 'ENABLED':
            self.console.item("Real-time Protection", rt, 'ok')
        elif rt == 'DISABLED':
            self.console.item("Real-time Protection", rt, 'crit')
        else:
            self.console.item("Real-time Protection", rt, 'warn')

        tp = self.results.get('tamper', 'UNKNOWN')
        if 'ENABLED' in tp:
            self.console.item("Tamper Protection", tp, 'ok')
        else:
            self.console.item("Tamper Protection", tp, 'warn')

        cp = self.results.get('cloud', 'UNKNOWN')
        if 'ENABLED' in cp:
            self.console.item("Cloud Protection", cp, 'ok')
        elif cp == 'DISABLED':
            self.console.item("Cloud Protection", cp, 'crit')
        else:
            self.console.item("Cloud Protection", cp, 'warn')

        bm = self.results.get('behavior', 'UNKNOWN')
        if bm == 'ENABLED':
            self.console.item("Behavior Monitor", bm, 'ok')
        elif bm == 'DISABLED':
            self.console.item("Behavior Monitor", bm, 'crit')
        else:
            self.console.item("Behavior Monitor", bm, 'warn')

        self.console.item("Signature Version", self.results.get('signature_ver', 'UNKNOWN'))

        cfa = self.results.get('controlled_folder')
        if cfa:
            if cfa == 'ENABLED':
                self.console.item("Controlled Folder Access", cfa, 'ok')
            else:
                self.console.item("Controlled Folder Access", cfa, 'warn')

        asr = self.results.get('asr_rules', {})
        enabled_rules = asr.get('enabled', [])
        disabled_rules = asr.get('disabled', [])
        asr_status = asr.get('status')

        self.console.subsection("ASR RULES")
        if asr_status == 'UNKNOWN':
            self.console.item("ASR Rules", "UNKNOWN (policy unreadable)", 'warn')
        elif asr_status == 'NOT CONFIGURED' and not enabled_rules and not disabled_rules:
            self.console.item("ASR Rules", "NOT CONFIGURED", 'warn')
        elif not enabled_rules and not disabled_rules:
            self.console.item("ASR Rules", "NOT CONFIGURED", 'warn')
        else:
            for rule_name, rule_id, action, min_ver in enabled_rules:
                self.console.item(rule_name[:40], f'ENABLED ({action})', 'ok')
            for rule_name, rule_id, min_ver in disabled_rules[:5]:
                self.console.item(rule_name[:40], 'DISABLED', 'off')
            if len(disabled_rules) > 5:
                self.console.info(f"  ... and {len(disabled_rules) - 5} more disabled rules")
            self.console.item("Total Enabled", str(len(enabled_rules)))
            self.console.item("Total Disabled", str(len(disabled_rules)))
