"""Kerberos hardening checks (Server 2016+, critical for Server 2025)"""


class KerberosCheck:
    """Check Kerberos hardening via registry reads"""

    # SupportedEncryptionTypes bitmask values
    ENC_DES_CRC = 0x01
    ENC_DES_MD4 = 0x02
    ENC_RC4_HMAC = 0x04
    ENC_AES128 = 0x08
    ENC_AES256 = 0x10
    ENC_AES_FUTURE = 0x20

    AES_ONLY = 0x7FFFFFF8  # All DES/RC4 bits masked off
    ALL_TYPES = 0x7FFFFFFF  # Everything allowed

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating Kerberos hardening (registry reads)...")

        if self.os_target and self.os_target.role_known and not self.os_target.is_domain_controller:
            self.results['encryption_types'] = 'NOT APPLICABLE'
            self.results['rc4_rejected'] = 'NOT APPLICABLE'
            self.results['max_ticket_age'] = 'NOT APPLICABLE'
            self.results['delegation_restricted'] = 'NOT APPLICABLE'
            return self.results

        self.results['encryption_types'] = self._check_encryption_types()
        self.results['rc4_rejected'] = self._check_rc4_rejection()
        self.results['max_ticket_age'] = self._check_max_ticket_age()
        self.results['delegation_restricted'] = self._check_delegation()

        if self.os_target and self.os_target.is_server_2025:
            self.results['fasp'] = self._check_fasp()
            self.results['pkt_check'] = self._check_pkt_check()

        return self.results

    def _reg(self, key, name, default='UNKNOWN'):
        from ..utils import reg_val
        return reg_val(self.transport, key, name, default)

    def _check_encryption_types(self):
        """Supported Kerberos encryption types.

        0x7FFFFFFF = all types including RC4 (bad)
        0x7FFFFFF8 = AES only (good)
        0x18 = AES128+AES256 only (good, minimal)
        0 = default (often means RC4 is still usable)
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters',
                    'SupportedEncryptionTypes', self.ALL_TYPES)
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return int(v) if v is not None else 0

    def _check_rc4_rejection(self):
        """Reject new RC4 connections (Server 2025+).

        1 = reject new RC4, 0 = allow (default on legacy).
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters',
                    'RejectNewRC4', 'DISABLED (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'DISABLED (by default)':
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_max_ticket_age(self):
        """Maximum Kerberos ticket lifetime in hours."""
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters',
                    'MaxTicketAge', '10 hours (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == '10 hours (by default)':
            return v
        return f'{v} hours'

    def _check_delegation(self):
        """OkAsDelegate — unconstrained delegation allowed.

        0 = disabled (restricted), 1 = allowed (risky).
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters',
                    'OkAsDelegate', 'ENABLED (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'ENABLED (by default)':
            return v
        return 'DISABLED' if v == 0 else 'ENABLED'

    def _check_fasp(self):
        """Flexible Authentication Secure Kerberos (Server 2025).

        FASP allows Kerberos pre-authentication with device certificates.
        """
        val = self._reg(
            r'HKLM\SYSTEM\CurrentControlSet\Services\Kdc',
            'EnableKdcSupportFASP')
        if val == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if val == 1 else 'DISABLED'

    def _check_pkt_check(self):
        """PAK (Pre-Authentication Key) cookie check (Server 2025).

        Mitigates Kerberoasting by requiring valid pre-auth data.
        """
        val = self._reg(
            r'HKLM\SYSTEM\CurrentControlSet\Services\Kdc',
            'EnablePKTCheck')
        if val == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if val == 1 else 'DISABLED'

    def _format_enc_types(self, value):
        """Human-readable summary of encryption type bitmask."""
        if value is None:
            return 'UNKNOWN'

        flags = []
        has_weak = False

        if value & self.ENC_DES_CRC:
            flags.append('DES-CRC')
            has_weak = True
        if value & self.ENC_DES_MD4:
            flags.append('DES-MD4')
            has_weak = True
        if value & self.ENC_RC4_HMAC:
            flags.append('RC4-HMAC')
            has_weak = True
        if value & self.ENC_AES128:
            flags.append('AES128')
        if value & self.ENC_AES256:
            flags.append('AES256')

        label = ', '.join(flags) if flags else f'0x{value:08x}'
        if has_weak:
            label += ' (WEAK CIPHERS PRESENT)'
        return label

    def display(self):
        self.console.section("KERBEROS HARDENING")

        etypes = self.results.get('encryption_types')
        if isinstance(etypes, int):
            if etypes == self.AES_ONLY or etypes & 0x18 == etypes:
                self.console.item("Encryption Types",
                                  self._format_enc_types(etypes), 'ok')
            else:
                self.console.item("Encryption Types",
                                  self._format_enc_types(etypes), 'warn')
        else:
            self.console.item("Encryption Types", 'UNKNOWN', 'warn')

        rc4 = self.results.get('rc4_rejected', 'UNKNOWN')
        if rc4 == 'ENABLED':
            self.console.item("RC4 Rejection", rc4, 'ok')
        elif rc4 == 'DISABLED':
            self.console.item("RC4 Rejection", rc4, 'warn')
        else:
            self.console.item("RC4 Rejection", rc4)

        age = self.results.get('max_ticket_age', 'UNKNOWN')
        self.console.item("Max Ticket Age", age)

        deleg = self.results.get('delegation_restricted', 'UNKNOWN')
        if deleg == 'DISABLED':
            self.console.item("Unconstrained Delegation", 'Restricted', 'ok')
        elif deleg == 'ENABLED':
            self.console.item("Unconstrained Delegation", 'Allowed', 'crit')
        else:
            self.console.item("Unconstrained Delegation", deleg)

        # Server 2025 features
        fasp = self.results.get('fasp')
        if fasp:
            if fasp == 'ENABLED':
                self.console.item("FASP (Kerberos)", fasp, 'ok')
            else:
                self.console.item("FASP (Kerberos)", fasp)

        pkt = self.results.get('pkt_check')
        if pkt:
            if pkt == 'ENABLED':
                self.console.item("PAK Cookie Check", pkt, 'ok')
            else:
                self.console.item("PAK Cookie Check", pkt, 'warn')
