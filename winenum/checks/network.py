"""Network protocol hardening checks (SMB, LDAP, Netlogon, RDP, NTLM)"""


class NetworkCheck:
    """Check network protocol hardening via registry (SMB, LDAP, Netlogon, RDP, NTLM)"""

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    def run(self):
        self.console.info("Enumerating network hardening (registry reads)...")

        self.results['smb_signing_required'] = self._check_smb_signing()
        self.results['smb_encryption'] = self._check_smb_encryption()
        self.results['smb_v1_disabled'] = self._check_smb_v1()
        self.results['ldap_signing'] = self._check_ldap_signing()
        self.results['ldap_channel_binding'] = self._check_ldap_channel_binding()
        self.results['netlogon_signing'] = self._check_netlogon_signing()
        self.results['netlogon_sealing'] = self._check_netlogon_sealing()
        self.results['rdp_nla'] = self._check_rdp_nla()
        self.results['rdp_encryption'] = self._check_rdp_encryption()
        self.results['ntlm_level'] = self._check_ntlm_level()
        self.results['ntlm_restriction'] = self._check_ntlm_restriction()

        return self.results

    # ── SMB ───────────────────────────────────────────────────────────

    def _check_smb_signing(self):
        """SMB server signing required.

        Registry 1 = required. Falls back to the live SMB negotiation
        (REQUIRED/NOT REQUIRED) so StdRegProv / restricted registry does not
        stay UNKNOWN when the session actually negotiated signing.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                    'RequireSecuritySignature', 'UNKNOWN')
        if v != 'UNKNOWN':
            return 'REQUIRED' if v == 1 else 'NOT REQUIRED'
        for method in ('get_smb_signing', 'get_capabilities'):
            try:
                getter = getattr(self.transport, method, None)
                if getter:
                    info = getter()
                    if isinstance(info, dict):
                        signing = info.get('smb_signing') or info.get('signing')
                        if signing in ('REQUIRED', 'NOT REQUIRED'):
                            return signing
                    elif info in ('REQUIRED', 'NOT REQUIRED'):
                        return info
            except Exception:
                continue
        return 'UNKNOWN'

    def _check_smb_encryption(self):
        """SMB encryption (AES-128-GCM/CCM).

        1 = enabled, 0 = disabled. Available Win10 1607+ / Server 2016+.
        """
        from ..utils import reg_val
        if self.os_target and not self.os_target.supports_smb_encryption:
            return 'NOT SUPPORTED'
        key = r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        v = reg_val(self.transport, key, 'EncryptData', 'DISABLED (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'DISABLED (by default)':
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_smb_v1(self):
        """SMBv1 status.

        0 = disabled (good), 1 = enabled (critical risk).
        Server 2025 may not have this key (SMBv1 fully removed).
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                    'SMB1', 'DISABLED (not installed)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'DISABLED (not installed)':
            return v
        return 'DISABLED' if v == 0 else 'ENABLED'

    # ── LDAP ──────────────────────────────────────────────────────────

    def _check_ldap_signing(self):
        """LDAP signing requirement.

        0 = none, 1 = negotiate, 2 = require signing.
        DC-only key: return NOT APPLICABLE on member/client hosts.
        """
        if self.os_target and self.os_target.role_known and not self.os_target.is_domain_controller:
            return 'NOT APPLICABLE'
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Services\NTDS',
                    'LDAPServerIntegrity', 'NONE (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'NONE (by default)':
            return v
        if v == 2:
            return 'REQUIRED'
        elif v == 1:
            return 'NEGOTIATE'
        return f'NONE ({v})'

    def _check_ldap_channel_binding(self):
        """LDAP channel binding.

        0 = disabled, 1 = when supported, 2 = always.
        DC-only key.
        """
        if self.os_target and self.os_target.role_known and not self.os_target.is_domain_controller:
            return 'NOT APPLICABLE'
        from ..utils import reg_val
        if self.os_target and not self.os_target.supports_ldap_channel_binding:
            return 'NOT SUPPORTED'
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Services\NTDS',
                    'LdapEnforceChannelBinding', 'WHEN SUPPORTED (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'WHEN SUPPORTED (by default)':
            return v
        if v == 2:
            return 'ALWAYS'
        elif v == 1:
            return 'WHEN SUPPORTED'
        return f'DISABLED ({v})'

    # ── Netlogon ──────────────────────────────────────────────────────

    def _check_netlogon_signing(self):
        """Netlogon secure channel signing.

        1 = required. Critical for preventing NTLM relay attacks.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
                    'RequireSecuritySignature', 'ENABLED (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'ENABLED (by default)':
            return v
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_netlogon_sealing(self):
        """Netlogon secure channel sealing.

        1 = required. Encrypts Netlogon traffic.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
                    'RequireStrongKey', 'UNKNOWN')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if v == 1 else 'DISABLED'

    # ── RDP ───────────────────────────────────────────────────────────

    def _check_rdp_nla(self):
        """RDP Network Level Authentication.

        1 = required, 0 = not required.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
                    'UserAuthentication', 'UNKNOWN')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        return 'ENABLED' if v == 1 else 'DISABLED'

    def _check_rdp_encryption(self):
        """RDP encryption level.

        1=Low, 2=Client Compatible, 3=High, 4=FIPS.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
                    'MinEncryptionLevel', 'UNKNOWN')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        levels = {1: 'LOW', 2: 'CLIENT COMPATIBLE', 3: 'HIGH', 4: 'FIPS'}
        return levels.get(v, f'LEVEL {v}')

    # ── NTLM ──────────────────────────────────────────────────────────

    def _check_ntlm_level(self):
        """NTLM authentication level (LmCompatibilityLevel).

        0-4 = allows LM/NTLMv1, 5 = NTLMv2 only.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
                    'LmCompatibilityLevel', 'Level 3 (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'Level 3 (by default)':
            return v
        if v >= 5:
            return 'NTLMv2 only'
        elif v >= 3:
            return f'Level {v} (NTLMv1 allowed)'
        return f'Level {v} (LM allowed)'

    def _check_ntlm_restriction(self):
        """Outbound NTLM restriction.

        0 = allow all (default), 1 = audit, 2 = block all.
        Server 2025 defaults to restriction.
        """
        from ..utils import reg_val
        v = reg_val(self.transport,
                    r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
                    'RestrictSendingNTLMTraffic', 'ALLOW ALL (by default)')
        if v == 'UNKNOWN':
            return 'UNKNOWN'
        if v == 'ALLOW ALL (by default)':
            return v
        if v == 2:
            return 'BLOCK ALL'
        elif v == 1:
            return 'AUDIT'
        return 'ALLOW ALL'

    def display(self):
        self.console.section("NETWORK HARDENING")

        # SMB
        self.console.subsection("SMB")
        smb_sign = self.results.get('smb_signing_required', 'UNKNOWN')
        if smb_sign == 'REQUIRED':
            self.console.item("Server Signing", smb_sign, 'ok')
        elif smb_sign == 'NOT REQUIRED':
            self.console.item("Server Signing", smb_sign, 'warn')
        else:
            self.console.item("Server Signing", smb_sign)

        smb_enc = self.results.get('smb_encryption', 'UNKNOWN')
        if smb_enc == 'ENABLED':
            self.console.item("Encryption", smb_enc, 'ok')
        elif smb_enc == 'DISABLED':
            self.console.item("Encryption", smb_enc, 'warn')
        else:
            self.console.item("Encryption", smb_enc)

        smb_v1 = self.results.get('smb_v1_disabled', 'UNKNOWN')
        if 'DISABLED' in str(smb_v1):
            self.console.item("SMBv1", smb_v1, 'ok')
        elif smb_v1 == 'ENABLED':
            self.console.item("SMBv1", smb_v1, 'crit')
        else:
            self.console.item("SMBv1", smb_v1)

        # LDAP
        self.console.subsection("LDAP")
        ldap_s = self.results.get('ldap_signing', 'UNKNOWN')
        if ldap_s == 'REQUIRED':
            self.console.item("Signing", ldap_s, 'ok')
        elif ldap_s == 'NEGOTIATE':
            self.console.item("Signing", ldap_s, 'warn')
        else:
            self.console.item("Signing", ldap_s)

        ldap_cb = self.results.get('ldap_channel_binding', 'UNKNOWN')
        if ldap_cb in ('ALWAYS', 'WHEN SUPPORTED'):
            self.console.item("Channel Binding", ldap_cb, 'ok')
        else:
            self.console.item("Channel Binding", ldap_cb, 'warn')

        # Netlogon
        self.console.subsection("NETLOGON")
        nl_sign = self.results.get('netlogon_signing', 'UNKNOWN')
        if nl_sign == 'ENABLED':
            self.console.item("Signing", nl_sign, 'ok')
        elif nl_sign == 'DISABLED':
            self.console.item("Signing", nl_sign, 'warn')
        else:
            self.console.item("Signing", nl_sign)

        nl_seal = self.results.get('netlogon_sealing', 'UNKNOWN')
        if nl_seal == 'ENABLED':
            self.console.item("Sealing", nl_seal, 'ok')
        elif nl_seal == 'DISABLED':
            self.console.item("Sealing", nl_seal, 'warn')
        else:
            self.console.item("Sealing", nl_seal)

        # RDP
        self.console.subsection("RDP")
        rdp_nla = self.results.get('rdp_nla', 'UNKNOWN')
        if rdp_nla == 'ENABLED':
            self.console.item("NLA", rdp_nla, 'ok')
        elif rdp_nla == 'DISABLED':
            self.console.item("NLA", rdp_nla, 'warn')
        else:
            self.console.item("NLA", rdp_nla)

        rdp_enc = self.results.get('rdp_encryption', 'UNKNOWN')
        if rdp_enc in ('HIGH', 'FIPS'):
            self.console.item("Encryption Level", rdp_enc, 'ok')
        elif rdp_enc in ('LOW', 'CLIENT COMPATIBLE'):
            self.console.item("Encryption Level", rdp_enc, 'warn')
        else:
            self.console.item("Encryption Level", rdp_enc)

        # NTLM
        self.console.subsection("NTLM")
        ntlm_lvl = self.results.get('ntlm_level', 'UNKNOWN')
        if ntlm_lvl == 'NTLMv2 only':
            self.console.item("Auth Level", ntlm_lvl, 'ok')
        elif 'LM allowed' in ntlm_lvl:
            self.console.item("Auth Level", ntlm_lvl, 'crit')
        else:
            self.console.item("Auth Level", ntlm_lvl, 'warn')

        ntlm_r = self.results.get('ntlm_restriction', 'UNKNOWN')
        if ntlm_r == 'BLOCK ALL':
            self.console.item("Outbound Restriction", ntlm_r, 'ok')
        elif ntlm_r == 'AUDIT':
            self.console.item("Outbound Restriction", ntlm_r, 'warn')
        else:
            self.console.item("Outbound Restriction", ntlm_r)
