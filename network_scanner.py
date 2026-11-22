#!/usr/bin/env python3
"""
Network Scanner - lists the devices connected to your home network.

How it works:
  1. Finds your computer's IP address, e.g. 192.168.1.5
  2. Pings every address in your network, e.g. 192.168.1.1 to 192.168.1.254
  3. Reads your computer's ARP table (a list of IP -> MAC address it has seen).
     This also finds devices that ignore pings, like many phones.
  4. Looks up each device's name, when the network provides one.

Uses only Python's standard library. Nothing to install.

How to run:
    python network_scanner.py                    (scan your own network)
    python network_scanner.py 192.168.0.0/24     (scan a specific range)
    python network_scanner.py --save devices.csv (also save results to a file)

IMPORTANT: Only scan networks you own or have permission to scan.
This tool refuses to scan public (internet) addresses.
"""

import argparse
import csv
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
MAX_HOSTS = 1024

IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")


def my_ip():
    """Find this computer's local IP. No data is actually sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def ping(ip, timeout_s=1):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 3)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    if r.returncode != 0:
        return False
    # On Windows, "Destination host unreachable" can still return 0. A real reply has "TTL=".
    return "TTL=" in r.stdout.upper() if IS_WINDOWS else True


def normalize_mac(mac):
    parts = re.split(r"[:-]", mac)
    return ":".join(p.zfill(2) for p in parts).upper()


def read_arp_table():
    """Return {ip: mac} from the computer's ARP table."""
    commands = [["arp", "-a"]] if IS_WINDOWS else [["arp", "-an"], ["ip", "neigh"]]
    table = {}
    for cmd in commands:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        for line in out.splitlines():
            ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
            if not ip_m or not mac_m:
                continue
            mac = normalize_mac(mac_m.group(1))
            first_byte = int(mac.split(":")[0], 16)
            if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or first_byte & 1:
                continue  # broadcast / multicast, not a real device
            table[ip_m.group(1)] = mac
        if table:
            break
    return table


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def main():
    parser = argparse.ArgumentParser(description="List devices on your local network.")
    parser.add_argument("network", nargs="?", help="range to scan, e.g. 192.168.1.0/24 (default: auto)")
    parser.add_argument("--save", metavar="FILE", help="save results to a CSV file")
    args = parser.parse_args()

    me = my_ip()

    # Which network?
    if args.network:
        try:
            net = ipaddress.ip_network(args.network, strict=False)
        except ValueError:
            sys.exit(f"Error: '{args.network}' is not a valid range. Example: 192.168.1.0/24")
    else:
        if not me:
            sys.exit("Error: could not find your IP. Are you connected to a network?")
        # Assumption: most home networks use a /24 (256 addresses).
        net = ipaddress.ip_network(f"{me}/24", strict=False)

    if net.version != 4:
        sys.exit("Error: only IPv4 networks are supported.")
    if not net.is_private:
        sys.exit(f"Error: {net} is not a private (home/office) network. "
                 "This tool only scans private networks.")
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    if len(hosts) > MAX_HOSTS:
        sys.exit(f"Error: {net} has {len(hosts)} addresses. The limit is {MAX_HOSTS}. Try a /24.")

    print(f"Your IP: {me or 'unknown'}")
    print(f"Scanning {net} ({len(hosts)} addresses). This takes about 10-30 seconds...\n")
    start = time.perf_counter()

    # Step 1: ping everything at once (64 at a time)
    targets = [str(h) for h in hosts]
    with ThreadPoolExecutor(max_workers=64) as pool:
        replied = {ip for ip, ok in zip(targets, pool.map(ping, targets)) if ok}

    # Step 2: read the ARP table (catches devices that ignore ping)
    arp = {ip: mac for ip, mac in read_arp_table().items()
           if ipaddress.ip_address(ip) in net}

    found = sorted(replied | set(arp) | ({me} if me and ipaddress.ip_address(me) in net else set()),
                   key=lambda ip: ipaddress.ip_address(ip))

    # Step 3: names
    with ThreadPoolExecutor(max_workers=32) as pool:
        names = dict(zip(found, pool.map(hostname, found)))

    rows = []
    for ip in found:
        how = "ping + ARP" if ip in replied and ip in arp else "ping" if ip in replied else "ARP only"
        note = "this computer" if ip == me else ""
        rows.append([ip, arp.get(ip, ""), names.get(ip, ""), how, note])

    print(f"{'IP address':16} {'MAC address':18} {'Name':28} {'Found by':11} Note")
    print("-" * 85)
    for ip, mac, name, how, note in rows:
        print(f"{ip:16} {mac or '-':18} {(name or '-')[:28]:28} {how:11} {note}")

    print(f"\nFound {len(rows)} device(s) in {time.perf_counter() - start:.1f}s.")
    print("Tip: run it twice. Some devices only show up on the second scan.")

    if args.save:
        with open(args.save, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "mac", "name", "found_by", "note"])
            w.writerows(rows)
        print(f"Saved to {args.save}")


if __name__ == "__main__":
    main()
