"""Port scanning checks (OPSEC-safe via SMB signing detection)"""
import socket


class PortCheck:
    """Scan common Windows services ports and check SMB signing"""

    PORTS = {
        445: 'SMB',
        135: 'WMI/RPC',
        5985: 'WinRM-HTTP',
        5986: 'WinRM-HTTPS',
        3389: 'RDP',
        22: 'SSH',
        389: 'LDAP',
        636: 'LDAPS',
        88: 'Kerberos',
    }

    def __init__(self, transport, console, os_target=None):
        self.transport = transport
        self.console = console
        self.os_target = os_target
        self.results = {}

    @staticmethod
    def _tcp_connect(host, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def run(self):
        self.console.info("Checking available ports (OPSEC: SMB signing)...")

        host = self.transport.target if hasattr(self.transport, 'target') else str(self.transport)
        checker = getattr(self.transport, 'check_port', None)
        open_ports = []

        for port, service in self.PORTS.items():
            try:
                is_open = checker(host, port) if checker else self._tcp_connect(host, port)
            except TypeError:
                is_open = self._tcp_connect(host, port)
            if is_open:
                open_ports.append((port, service))

        self.results['open_ports'] = open_ports
        self.results['host'] = host

        if hasattr(self.transport, 'get_smb_signing'):
            self.results['smb_signing'] = self.transport.get_smb_signing()
        if hasattr(self.transport, 'get_smb_version'):
            self.results['smb_version'] = self.transport.get_smb_version()

        return self.results

    def display(self):
        self.console.section("NETWORK SERVICES")

        open_ports = self.results.get('open_ports', [])
        host = self.results.get('host', 'UNKNOWN')

        if open_ports:
            self.console.success(f"Open ports on {host}:")
            for port, service in sorted(open_ports):
                self.console.item(f"{service}", f"Port {port}", 'ok')
        else:
            self.console.warning(f"No common ports open on {host}")

        signing = self.results.get('smb_signing')
        if signing:
            if signing == 'REQUIRED':
                self.console.item("SMB Signing", signing, 'ok')
            else:
                self.console.item("SMB Signing", signing, 'warn')

        version = self.results.get('smb_version')
        if version:
            self.console.item("SMB Version", version)
