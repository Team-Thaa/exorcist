import argparse
import json
import sys

from .scanner import scan_network


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find common TCP services on an authorized private IPv4 subnet."
    )
    parser.add_argument(
        "--network",
        required=True,
        help="RFC 1918 subnet to scan, limited to /24 or smaller (for example 192.168.1.0/24)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.25,
        help="TCP connection timeout in seconds (0.05-2, default: 0.25)",
    )
    args = parser.parse_args()

    try:
        devices = scan_network(args.network, timeout=args.timeout)
    except ValueError as exc:
        parser.error(str(exc))

    json.dump(devices, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
