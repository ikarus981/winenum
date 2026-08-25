#!/usr/bin/env python3
"""
winenum - Windows security configuration enumeration

Read selected Windows security controls remotely through authenticated
SMB/MS-RRP, WMI/DCOM, and MS-RPC transports.

Usage:
    python winenum.py domain/username:password@target
    python winenum.py administrator:pass123@192.168.1.100
    python winenum.py user@10.0.0.1
"""

import sys
from winenum.cli import main

if __name__ == '__main__':
    sys.exit(main())
