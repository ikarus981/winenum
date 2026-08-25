"""CLI entry point for winenum."""
import argparse

from .output.console import Console
from .enum import WinEnum
from .utils import parse_target, parse_hashes


def build_parser():
    parser = argparse.ArgumentParser(
        description='winenum - Windows security configuration enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 winenum.py DOMAIN/user@host.example.com
  python3 winenum.py DOMAIN/user@dc.example.com -k --no-pass --dc-ip 192.0.2.10
  python3 winenum.py DOMAIN/user@dc.example.com --aes-key <hex-key> --dc-ip 192.0.2.10
        '''
    )
    parser.add_argument('target', help='[domain/]username[:password]@host')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--json', action='store_true',
                        help='Emit only the structured JSON report')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('--hashes', metavar='LMHASH:NTHASH',
                      help='NTLM hashes (LM:NT or just NT for pass-the-hash)')
    auth.add_argument('--no-pass', action='store_true',
                      help='Do not prompt/use password (with -k uses ccache)')
    auth.add_argument('--aes-key', '-aes-key', metavar='HEX',
                      help='AES key for Kerberos authentication')
    auth.add_argument('-k', '--kerberos', action='store_true',
                      help='Use Kerberos authentication (honors KRB5CCNAME)')
    auth.add_argument('--dc-ip', metavar='IP',
                      help='IP of the domain controller (KDC)')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    # parse_target returns (domain, username, password, host)
    domain, user, password, host = parse_target(args.target)
    lmhash, nthash = parse_hashes(args.hashes)

    if args.no_pass and not args.kerberos:
        # pass-the-hash with no password string is fine; just clear pw
        password = ''

    if not host:
        console = Console()
        console.error("Invalid target format. Use: [domain/]username[:password]@host")
        return 1

    console = Console(debug=args.verbose, quiet=args.json)
    kerberos_ccache = None
    kerberos_ccache_source = None
    if args.kerberos:
        import os as _os
        from .utils.krb5 import resolve_ccache as _resolve_ccache
        was_env = _os.environ.get('KRB5CCNAME')
        kerberos_ccache = _resolve_ccache(None)
        if kerberos_ccache and not was_env:
            _os.environ['KRB5CCNAME'] = kerberos_ccache
            kerberos_ccache_source = 'autodetected'
        elif was_env:
            kerberos_ccache_source = 'env'
        if kerberos_ccache and not args.no_pass and not args.aes_key and not args.hashes:
            args.no_pass = True
    if not args.json:
        console.banner()
        console.info(f"Target: {host}")
        console.info(f"User: {domain}\\{user}" if domain else f"User: {user}")
        if args.kerberos:
            import os
            cc = os.environ.get('KRB5CCNAME') or kerberos_ccache
            if cc:
                detail = f" (ccache: {cc})"
            else:
                detail = " (ccache: none, will request TGT)"
            console.info(f"Kerberos: enabled{detail}"
                         f"{f' KDC: {args.dc_ip}' if args.dc_ip else ''}")
            if args.verbose and kerberos_ccache:
                if kerberos_ccache_source == 'autodetected':
                    console.debug_msg(f"Using KRB5CCNAME autodetected: {kerberos_ccache}")
                elif kerberos_ccache_source == 'env':
                    console.debug_msg(f"Using KRB5CCNAME from environment: {kerberos_ccache}")
        console.blank()

    try:
        from .connection.auto import TransportManager
    except ImportError as exc:
        if args.json:
            console.json_output({
                'tool': 'winenum',
                'target': host,
                'error': 'dependency_error',
                'detail': str(exc),
            })
        else:
            console.error(
                f"Unable to load the transport dependency: {exc}. "
                "Install requirements.txt."
            )
        return 1

    manager = TransportManager(host, console=console, timeout=args.timeout)
    connection = manager.auto_connect(
        user, password, domain,
        lmhash=lmhash, nthash=nthash,
        aes_key=args.aes_key or '',
        dc_ip=args.dc_ip or '',
        use_kerberos=bool(args.kerberos),
    )

    if not connection:
        if args.json:
            Console().json_output({
                'tool': 'winenum',
                'target': host,
                'error': 'connection_failed',
            })
        else:
            console.error("Failed to connect to target")
        return 1

    try:
        if not args.json:
            console.info(f"Connected via {connection.__class__.__name__} "
                         f"(transport: {manager.transport_type})")
            console.blank()

        enumerator = WinEnum(connection, console, host)
        enumerator.run_all()

        level, msg = enumerator.get_risk_assessment()
        if args.json:
            from .utils import process_results_for_json
            payload = process_results_for_json(
                enumerator.all_results,
                target=host,
                transport=manager.transport_type,
                assessment={'level': level, 'message': msg},
            )
            console.json_output(payload)
        else:
            console.section("ASSESSMENT")
            console.assessment_line(level, msg)
    finally:
        if hasattr(connection, 'close'):
            try:
                connection.close()
            except Exception:
                pass

    if not args.json:
        console.blank()
        console.info("Enumeration complete.")
        console.blank()
    return 0
