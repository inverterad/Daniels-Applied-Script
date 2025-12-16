#!/usr/bin/env python3
import os
import sys
import logging
import argparse
from datetime import datetime

SCRIPT_NAME = "Security Scan Script"
VERSION = "1.0"
LOG_FILE = "/var/log/security_scan.log"

# -------------------------------------------------
# Kontroll: root
# -------------------------------------------------
def check_root():
    if os.geteuid() != 0:
        print("Fel: Scriptet måste köras som root.")
        sys.exit(1)

# -------------------------------------------------
# Loggning
# -------------------------------------------------
def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.info("Script startat")

# -------------------------------------------------
# Systeminformation
# -------------------------------------------------
def collect_system_info():
    info = {
        "user": os.getenv("SUDO_USER", "unknown"),
        "hostname": os.uname().nodename,
        "kernel": os.uname().release
    }
    logging.info(f"Systeminfo: {info}")
    return info

# -------------------------------------------------
# Subnet-scan (simulerad)
# -------------------------------------------------
def subnet_scan():
    logging.info("Startar subnet-scan")
    return ["192.168.1.1", "192.168.1.10"]

# -------------------------------------------------
# Kernel / OS-kontroll
# -------------------------------------------------
def kernel_os_check():
    kernel = os.uname().release
    logging.info(f"Kernelversion: {kernel}")
    return kernel

# -------------------------------------------------
# Öppna portar (simulerad)
# -------------------------------------------------
def open_ports_scan():
    logging.info("Kontrollerar öppna portar")
    return [22, 80]

# -------------------------------------------------
# Sammanställning
# -------------------------------------------------
def summarize_results(info, hosts, ports):
    summary = {
        "system": info,
        "hosts_found": len(hosts),
        "open_ports": ports
    }
    logging.info(f"Sammanfattning: {summary}")
    return summary

# -------------------------------------------------
# Argumenthantering
# -------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Automatiserat säkerhetsscript för system- och nätverkskontroll"
    )
    parser.add_argument(
        "-v", "--version",
        action="store_true",
        help="Visa scriptets version"
    )
    return parser.parse_args()

# -------------------------------------------------
# MAIN
# -------------------------------------------------
def main():
    args = parse_arguments()

    if args.version:
        print(f"{SCRIPT_NAME} - version {VERSION}")
        sys.exit(0)

    check_root()
    setup_logging()

    try:
        info = collect_system_info()
        hosts = subnet_scan()
        kernel_os_check()
        ports = open_ports_scan()

        summary = summarize_results(info, hosts, ports)

        print("\nScan klar\n")

        print("Nätverk:")
        print(f"- Antal hittade hosts: {summary.get('hosts_found', 'N/A')}\n")

        print("Öppna portar:")
        for port in summary.get("open_ports", []):
            print(f"- {port}")

        print(f"\nFullständig logg: {LOG_FILE}")

        logging.info("Script avslutades korrekt")

    except Exception as e:
        logging.error(f"Fel uppstod: {e}")
        print("Ett fel uppstod. Se loggfilen för detaljer.")
        sys.exit(1)

# -------------------------------------------------
if __name__ == "__main__":
    main()
