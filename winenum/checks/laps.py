"""Windows LAPS configuration checks"""


class LAPSCheck:
    """Check Windows LAPS (Local Admin Password Solution) configuration"""

    LAPS_POLICY_PATH = r'HKLM\SOFTWARE\Policies\Microsoft\Psd\Laps'

    BACKUP_DIRS = {
        0: 'NOT CONFIGURED',
        1: 'AD',
        2: 'AZURE AD',
    }

    COMPLEXITY = {
        1: 'LETTERS',
        2: 'DIGITS',
        3: 'MIXED CASE',
        4: 'ANY CHARACTERS',
    }

    POST_AUTH_ACTIONS = {
        0: 'NONE',
        1: 'RESET PASSWORD',
        2: 'LOGOFF',
        4: 'DISCONNECT RDP',
        8: 'NOTIFY',
    }

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating Windows LAPS (registry reads)...")

        self.results['backup_directory'] = self._check_backup_dir()
        self.results['password_length'] = self._check_password_length()
        self.results['password_complexity'] = self._check_password_complexity()
        self.results['password_age'] = self._check_password_age()
        self.results['expiration_protection'] = self._check_expiration_protection()

        # Server 2025 / Win11 24H2 additions
        if self.os_target and (self.os_target.build or 0) >= 26100:
            self.results['ad_encryption'] = self._check_ad_encryption()
            self.results['post_auth_actions'] = self._check_post_auth_actions()
            self.results['post_auth_delay'] = self._check_post_auth_delay()

        return self.results

    def _reg(self, name):
        """Read a LAPS policy value.

        Returns REG_NOT_FOUND when the value legitimately does not exist,
        None when the registry backend is not functional.
        """
        if not hasattr(self.transport, 'get_registry_value'):
            return None
        return self.transport.get_registry_value(self.LAPS_POLICY_PATH, name)

    def _laps(self, name, default='NOT CONFIGURED'):
        """Resolve a LAPS value: real value / NOT CONFIGURED (absent) /
        UNKNOWN (registry backend not functional, no fabrication)."""
        from ..utils import REG_NOT_FOUND
        v = self._reg(name)
        if v is REG_NOT_FOUND:
            return default
        if v is None:
            return 'UNKNOWN'
        return v

    def _check_backup_dir(self):
        """Backup directory: 0=disabled, 1=AD, 2=Azure AD."""
        v = self._laps('BackupDirectory')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return v
        return self.BACKUP_DIRS.get(int(v), f'UNKNOWN ({v})')

    def _check_password_length(self):
        """Minimum password length (characters). Default is 14."""
        return self._laps('PasswordLength')

    def _check_password_complexity(self):
        """Password complexity: 1=letters, 2=digits, 3=mixed, 4=any."""
        v = self._laps('PasswordComplexity')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return v
        return self.COMPLEXITY.get(int(v), f'UNKNOWN ({v})')

    def _check_password_age(self):
        """Maximum password age in days before rotation."""
        v = self._laps('PasswordAgeDays')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return v
        return f'{v} days'

    def _check_expiration_protection(self):
        """Expiration protection prevents password use after expiry."""
        v = self._laps('PasswordExpirationProtectionEnabled')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_ad_encryption(self):
        """AD password encryption (Server 2025: AES-256-GCM)."""
        v = self._laps('ADPasswordEncryptionEnabled')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_post_auth_actions(self):
        """Actions after post-authentication password use.

        Bitmask: 1=reset, 2=logoff, 4=disconnect RDP, 8=notify.
        """
        v = self._laps('PostAuthenticationActions')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return v
        actions = []
        v = int(v)
        for bit, name in self.POST_AUTH_ACTIONS.items():
            if v & bit:
                actions.append(name)
        return ', '.join(actions) if actions else 'NONE'

    def _check_post_auth_delay(self):
        """Hours to wait before executing post-auth actions."""
        v = self._laps('PostAuthenticationResetDelay')
        if v in ('UNKNOWN', 'NOT CONFIGURED'):
            return v
        return f'{v} hours'

    def display(self):
        self.console.section("WINDOWS LAPS")

        backup = self.results.get('backup_directory', 'UNKNOWN')
        if backup in ('AD', 'AZURE AD'):
            self.console.item("Backup Directory", backup, 'ok')
        elif backup == 'NOT CONFIGURED':
            self.console.item("Backup Directory", backup, 'warn')
        else:
            self.console.item("Backup Directory", backup)

        pw_len = self.results.get('password_length', 'UNKNOWN')
        if pw_len != 'UNKNOWN':
            try:
                if int(pw_len) >= 14:
                    self.console.item("Password Length", pw_len, 'ok')
                else:
                    self.console.item("Password Length", pw_len, 'warn')
            except ValueError:
                self.console.item("Password Length", pw_len)
        else:
            self.console.item("Password Length", pw_len)

        complexity = self.results.get('password_complexity', 'UNKNOWN')
        if complexity in ('MIXED CASE', 'ANY CHARACTERS'):
            self.console.item("Password Complexity", complexity, 'ok')
        elif complexity in ('LETTERS', 'DIGITS'):
            self.console.item("Password Complexity", complexity, 'warn')
        else:
            self.console.item("Password Complexity", complexity)

        age = self.results.get('password_age', 'UNKNOWN')
        self.console.item("Max Password Age", age)

        exp = self.results.get('expiration_protection', 'UNKNOWN')
        if exp == 'ENABLED':
            self.console.item("Expiration Protection", exp, 'ok')
        elif exp == 'DISABLED':
            self.console.item("Expiration Protection", exp, 'warn')
        else:
            self.console.item("Expiration Protection", exp)

        # Server 2025 features
        ad_enc = self.results.get('ad_encryption')
        if ad_enc:
            if ad_enc == 'ENABLED':
                self.console.item("AD Encryption (AES-256)", ad_enc, 'ok')
            else:
                self.console.item("AD Encryption (AES-256)", ad_enc, 'warn')

        post_auth = self.results.get('post_auth_actions')
        if post_auth:
            self.console.item("Post-Auth Actions", post_auth)

        post_delay = self.results.get('post_auth_delay')
        if post_delay:
            self.console.item("Post-Auth Delay", post_delay)
