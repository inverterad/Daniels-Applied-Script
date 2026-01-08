#!/usr/bin/env python3
"""
Security Scan Script (Applied Script)

Gör en enkel säkerhetskontroll i Linux:
- kräver Linux + sudo
- samlar systeminfo
- (valfritt) samlar nätverksinfo
- listar öppna portar
- (valfritt) listar SUID-filer
- loggar allt till logs/security_scan.log
"""

import os
import sys
import argparse
import logging
import platform
import subprocess
from pathlib import Path


# ----- Inställningar -----
SCRIPT_NAME = "Security Scan Script"
VERSION = "1.2"
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_scan.log"


# ----- Kör ett Linux-kommando och returnera output -----
def run_command(command, max_lines=30):
    result = subprocess.run(command, capture_output=True, text=True)

    # Logga vilket kommando som kördes
    logging.info(f"Kör kommando: {' '.join(command)} | return code: {result.returncode}")

    # Ta output (stdout om det finns, annars stderr)
    output = (result.stdout or result.stderr).strip()

    # Logga bara en del av output så loggen inte blir jättestor
    if output:
        lines = output.splitlines()
        if len(lines) > max_lines:
            logging.info("Output (utdrag):\n" + "\n".join(lines[:max_lines]) + "\n... (truncated)")
        else:
            logging.info("Output:\n" + output)

    return output


# ----- Kontroll: Linux -----
def check_linux():
    if platform.system() != "Linux":
        print("Fel: Scriptet måste köras på Linux.")
        sys.exit(1)


# ----- Kontroll: sudo/root -----
def check_root():
    if os.geteuid() != 0:
        print("Fel: Scriptet måste köras med sudo (root).")
        sys.exit(1)


# ----- Starta loggning -----
def setup_logging():
    LOG_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.info("Script startat")


# ----- Systeminfo -----
def collect_system_info():
    user = os.getenv("SUDO_USER") or os.getenv("USER") or "unknown"
    hostname = run_command(["hostname"])
    kernel = run_command(["uname", "-r"])
    uptime = run_command(["uptime"])
    return {"user": user, "hostname": hostname, "kernel": kernel, "uptime": uptime}


# ----- Nätverksinfo -----
def collect_network_info():
    ip_info = run_command(["ip", "a"])
    routes = run_command(["ip", "r"])
    return {"ip": ip_info, "routes": routes}


# ----- Öppna portar -----
def scan_open_ports(quick):
    if quick:
        output = run_command(["ss", "-tuln"])
    else:
        output = run_command(["ss", "-tulpen"])
    return [line for line in output.splitlines() if line.strip()]


# ----- Valfri kontroll: SUID -----
def suid_check(limit=20):
    cmd = ["bash", "-lc", f"find / -perm -4000 -type f 2>/dev/null | head -n {limit}"]
    output = run_command(cmd)
    return [line for line in output.splitlines() if line.strip()]


# ----- Flaggar -----
def parse_arguments():
    parser = argparse.ArgumentParser(description="Automatiserat säkerhetsscript för Linux-system")
    parser.add_argument("-v", "--version", action="store_true", help="Visa version")
    parser.add_argument("--quick", action="store_true", help="Snabbare portlista")
    parser.add_argument("--no-network", action="store_true", help="Hoppa över nätverkskontroller")
    parser.add_argument("--suid", action="store_true", help="Lista SUID-filer (valfritt)")
    return parser.parse_args()


def main():
    args = parse_arguments()

    # Visa version och avsluta
    if args.version:
        print(f"{SCRIPT_NAME} – version {VERSION}")
        sys.exit(0)

    # Förkontroller
    check_linux()
    check_root()

    # Starta loggning
    setup_logging()

    try:
        # 1) Systeminfo
        system_info = collect_system_info()

        # 2) Nätverk (valfritt)
        network_info = None
        if not args.no_network:
            network_info = collect_network_info()

        # 3) Öppna portar
        ports = scan_open_ports(args.quick)

        # 4) SUID (valfritt)
        suid_results = None
        if args.suid:
            suid_results = suid_check(limit=20)

        # ----- Skriv ut resultat -----
        print("\n=== Scan klar ===\n")

        print("Systeminformation:")
        print(f"- Användare: {system_info['user']}")
        print(f"- Hostname: {system_info['hostname']}")
        print(f"- Kernel: {system_info['kernel']}")
        print(f"- Uptime: {system_info['uptime']}")

        if network_info:
            print("\nNätverk:")
            print("- IP-information och routing insamlad")

        print("\nÖppna portar:")
        if len(ports) == 0:
            print("- Inga lyssnande portar hittades.")
        else:
            for line in ports[:15]:
                print(line)

        if suid_results is not None:
            print("\nSUID-filer (utdrag):")
            if len(suid_results) == 0:
                print("- Inga resultat (eller saknar behörighet).")
            else:
                for line in suid_results:
                    print(line)

        print(f"\nLoggfil sparad i: {LOG_FILE}")
        logging.info("Script avslutades korrekt")

    except Exception:
        logging.exception("Ett fel inträffade")
        print("Ett fel inträffade. Se loggfilen för detaljer.")
        sys.exit(1)


if __name__ == "__main__":
    main()
