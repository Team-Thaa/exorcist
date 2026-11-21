import argparse
import json
import os
import sys

from .inventory import discover_devices, read_arp_table, read_conn_log


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a passive LAN device inventory from Zeek conn.log JSON."
    )
    parser.add_argument(
        "--conn-log",
        default=os.path.join(os.environ.get("ZEEK_LOG_DIR", "/opt/zeek/logs/current"), "conn.log"),
        help="Zeek JSON conn.log path (default: $ZEEK_LOG_DIR/conn.log)",
    )
    parser.add_argument(
        "--lan-cidr",
        default=os.environ.get("LAN_CIDR", "192.168.50.0/24"),
        help="LAN network to include (default: $LAN_CIDR or 192.168.50.0/24)",
    )
    parser.add_argument("--gateway-ip", default=os.environ.get("GATEWAY_IP", "192.168.50.1"))
    parser.add_argument("--decoy-ip", default=os.environ.get("DECOY_IP", "192.168.50.99"))
    args = parser.parse_args()

    try:
        rows = read_conn_log(args.conn_log)
        devices = discover_devices(
            rows,
            lan_cidr=args.lan_cidr,
            arp_table=read_arp_table(),
            gateway_ip=args.gateway_ip,
            decoy_ip=args.decoy_ip,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    json.dump(devices, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
