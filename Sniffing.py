import argparse
import os

from primary import PacketSniffer
from console import OutputToScreen

parser = argparse.ArgumentParser(description="Network packet sniffer")
parser.add_argument(
    "-i", "--interface",
    type=str,
    default=None,
    help="Interface to capture Ethernet frames (captures on all by default)."
)
parser.add_argument(
    "-d", "--data",
    action="store_true",
    help="Output packet data during capture."
)
_args = parser.parse_args()

if os.geteuid() != 0:
    raise SystemExit("Error: Permission denied. This application requires administrator privileges to run.")
    
sniffer = PacketSniffer()
OutputToScreen(subject=sniffer, display_data=_args.data)

try:
    for _ in sniffer.listen(_args.interface):
        pass
except KeyboardInterrupt:
    raise SystemExit("[!] Aborting packet capture...")
