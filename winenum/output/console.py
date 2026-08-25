"""Console output helpers."""
import sys
from datetime import datetime


class Console:
    """Small console renderer used by the command-line interface."""

    COLORS = {
        'green': '\033[92m',
        'yellow': '\033[93m',
        'red': '\033[91m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m',
    }

    def __init__(self, timestamp=False, debug=False, quiet=False):
        self.timestamp = timestamp
        self.debug = debug
        self.quiet = quiet
        self._use_color = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

    def _colorize(self, text, color):
        if self._use_color:
            return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"
        return str(text)

    def _ts(self):
        if self.timestamp:
            return f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
        return ""

    def banner(self):
        if self.quiet:
            return
        print()
        print(self._colorize("  winenum v0.2.0", 'cyan'))
        print(self._colorize("  Windows security configuration enumeration", 'white'))
        print()

    def info(self, msg):
        if self.quiet:
            return
        if msg is None or not str(msg).strip():
            return
        print(f"{self._ts()}[*] {msg}")

    def blank(self):
        if self.quiet:
            return
        print()

    def success(self, msg):
        if not self.quiet:
            print(f"{self._ts()}{self._colorize('[+]', 'green')} {msg}")

    def warning(self, msg):
        if not self.quiet:
            print(f"{self._ts()}{self._colorize('[!]', 'yellow')} {msg}")

    def error(self, msg):
        if not self.quiet:
            print(f"{self._ts()}{self._colorize('[-]', 'red')} {msg}")

    def debug_msg(self, msg):
        if self.debug and not self.quiet:
            print(f"{self._ts()}[DEBUG] {msg}")

    def section(self, title):
        if self.quiet:
            return
        print()
        print("=" * 60)
        print(f"  {title.upper()}")
        print("=" * 60)

    def subsection(self, title):
        if self.quiet:
            return
        print()
        print(f"  {title}")
        print("-" * 60)

    def item(self, key, value, status=None):
        if self.quiet:
            return
        key_padded = str(key).ljust(20)
        if status == 'ok':
            indicator = self._colorize('[+]', 'green')
            value_str = self._colorize(value, 'green')
        elif status == 'warn':
            indicator = self._colorize('[!]', 'yellow')
            value_str = self._colorize(value, 'yellow')
        elif status == 'crit':
            indicator = self._colorize('[!]', 'red')
            value_str = self._colorize(value, 'red')
        elif status == 'off':
            indicator = self._colorize('[-]', 'red')
            value_str = self._colorize(value, 'red')
        else:
            indicator = '   '
            value_str = str(value)
        print(f"  {indicator} {key_padded}: {value_str}")

    def assessment_line(self, level, msg):
        if self.quiet:
            return
        colors = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green', 'INFO': 'cyan'}
        color = colors.get(str(level).upper())
        if color:
            prefix = self._colorize('[!]' if level != 'INFO' else '[*]', color)
            message = self._colorize(msg, color)
        else:
            prefix = '[*]'
            message = str(msg)
        print(f"  {prefix} {message}")

    def risk_level(self, level, msg):
        if self.quiet:
            return
        colors = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green', 'INFO': 'cyan'}
        color = colors.get(level, 'white')
        print()
        print(f"  Risk Level: {self._colorize(level, color)} - {msg}")
        print()

    def json_output(self, payload):
        import json
        print(json.dumps(payload, indent=2, ensure_ascii=False))
