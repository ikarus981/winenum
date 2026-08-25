"""Windows version, edition, and role model."""


class OSTarget:
    """Represent the target OS and the checks that apply to it."""

    def __init__(self, caption='', build_number='', version='', product_type=None,
                 domain_role=None, ubr=None, product_name=''):
        self.caption = str(caption or '')
        self.build = self._to_int(build_number)
        self.version = str(version or '')
        self.product_type = self._to_int(product_type)
        self.domain_role = self._to_int(domain_role)
        self.ubr = self._to_int(ubr)
        self.product_name = str(product_name or '')
        self.is_server = self._detect_server()
        self.is_domain_controller = self._detect_domain_controller()

    @staticmethod
    def _to_int(value):
        if value in (None, ''):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _detect_server(self):
        if self.product_type in (2, 3):
            return True
        text = f'{self.caption} {self.product_name}'.lower()
        return 'server' in text

    def _detect_domain_controller(self):
        if self.product_type == 2:
            return True
        return self.domain_role in (4, 5)

    @property
    def role_known(self):
        return (
            self.product_type in (1, 2, 3)
            or self.domain_role in (0, 1, 2, 3, 4, 5)
        )

    @property
    def is_win10(self):
        return 10240 <= (self.build or 0) < 22000 and not self.is_server

    @property
    def is_win10_1803_plus(self):
        return 17134 <= (self.build or 0) < 22000 and not self.is_server

    @property
    def is_win10_1903_plus(self):
        return 18362 <= (self.build or 0) < 22000 and not self.is_server

    @property
    def is_win10_2004_plus(self):
        return 19041 <= (self.build or 0) < 22000 and not self.is_server

    @property
    def is_win11(self):
        return 22000 <= (self.build or 0) < 26100 and not self.is_server

    @property
    def is_win11_22h2_plus(self):
        return 22621 <= (self.build or 0) < 26100 and not self.is_server

    @property
    def is_win11_24h2(self):
        return (self.build or 0) >= 26100 and not self.is_server

    @property
    def is_server_2016_plus(self):
        return self.is_server and (self.build or 0) >= 14393

    @property
    def is_server_2019_plus(self):
        return self.is_server and (self.build or 0) >= 17763

    @property
    def is_server_2022(self):
        return self.is_server and 20348 <= (self.build or 0) < 26100

    @property
    def is_server_2025(self):
        return self.is_server and (self.build or 0) >= 26100

    @property
    def supports_hvci_wmi(self):
        return (self.build or 0) >= 14393

    @property
    def supports_asr_full(self):
        return (self.build or 0) >= 17134

    @property
    def supports_smart_app_control(self):
        return not self.is_server and (self.build or 0) >= 22000

    @property
    def supports_ppl_new_path(self):
        return (self.build or 0) >= 22621 or self.is_server_2025

    @property
    def supports_cet(self):
        return (self.build or 0) >= 19041

    @property
    def supports_kernel_shadow_stacks(self):
        return self.is_win11 or self.is_win11_24h2

    @property
    def supports_laps_v2(self):
        return (self.build or 0) >= 19041

    @property
    def supports_ppl_mode(self):
        return (self.build or 0) >= 26100

    @property
    def supports_controlled_folder_access(self):
        return (self.build or 0) >= 16299

    @property
    def supports_smb_encryption(self):
        return (self.build or 0) >= 14393

    @property
    def supports_ldap_channel_binding(self):
        return (self.build or 0) >= 10240

    @property
    def friendly_name(self):
        if self.is_server_2025:
            return 'Windows Server 2025'
        if self.is_server_2022:
            return 'Windows Server 2022'
        if self.is_server and (self.build or 0) >= 17763:
            return 'Windows Server 2019'
        if self.is_server and (self.build or 0) >= 14393:
            return 'Windows Server 2016'
        if self.is_server:
            return 'Windows Server'
        if self.is_win11_24h2:
            return 'Windows 11 24H2'
        if self.is_win11_22h2_plus:
            return 'Windows 11 22H2+'
        if self.is_win11:
            return 'Windows 11'
        if self.is_win10_2004_plus:
            return 'Windows 10 2004+'
        if self.is_win10_1903_plus:
            return 'Windows 10 1903+'
        if self.is_win10_1803_plus:
            return 'Windows 10 1803+'
        if self.is_win10:
            return 'Windows 10'
        if self.build:
            return f'Windows (Build {self.build})'
        return 'Windows (unknown version)'

    @property
    def role_name(self):
        if not self.role_known:
            return 'unknown'
        if self.is_domain_controller:
            return 'domain controller'
        if self.is_server:
            return 'member server or standalone server'
        return 'client/workstation'

    def __repr__(self):
        return (
            f'OSTarget(build={self.build}, server={self.is_server}, '
            f'dc={self.is_domain_controller}, name={self.friendly_name!r})'
        )
