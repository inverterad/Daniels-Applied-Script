#!/usr/bin/env python3
"""
Projektuppgift – Applied Script

Detta script gör en enkel säkerhetskontroll på ett Linux-system:
- Kontrollerar att scriptet körs på Linux och med sudo/root
- Samlar system- och nätverksinformation
- Listar öppna portar
- (Valfritt) listar SUID-filer
- Loggar allt till en fil för spårbarhet
"""

import os
import sys
import argparse
import logging
import platform
import subprocess
from pathlib import Path


# -----------------------------
# Grundinställningar
# -----------------------------
SCRIPT_NAME = "Security Scan Script"
VERSION = "1.1"

# Logg sparas i projektet (så det funkar även utan /var/log-behörighet)
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_scan.log"


# -----------------------------
# Kör kommandon i Linux (hjälpfunktion)
# -----------------------------
def run_command(command, max_lines=30):
    """
    Kör ett Linux-kommando och returnerar text (output).

    Vi loggar också kommandot och en del av outputen.
    max_lines gör att loggen inte blir enorm om kommandot skriver mycket.
    """
    result = subprocess.run(command, capture_output=True, text=True)

    # Logga vilket kommando som kördes och om det lyckades (0 = OK)
    logging.info(f"Kör kommando: {' '.join(command)} | return code: {result.returncode}")

    # Ta stdout om det finns, annars stderr (så vi får med fel om det uppstår)
    output = (result.stdout if result.stdout else result.stderr).strip()

    # Logga output (men begränsa mängden rader)
    if output:
        lines = output.splitlines()

        if len(lines) > max_lines:
            preview = "\n".join(lines[:max_lines])
            logging.info(f"Output (första {max_lines} rader):\n{preview}\n... (truncated)")
        else:
            logging.info(f"Output:\n{output}")

    return output


# -----------------------------
# Förkontroller (innan vi kör något)
# -----------------------------
def check_linux():
    """Stoppar scriptet om vi inte kör på Linux."""
    if platform.system() != "Linux":
        print("Fel: Scriptet måste köras på Linux.")
        sys.exit(1)


def check_root():
    """Stoppar scriptet om vi inte kör med sudo/root."""
    if os.geteuid() != 0:
        print("Fel: Scriptet måste köras med sudo (root).")
        sys.exit(1)


# -----------------------------
# Loggning
# -----------------------------
def setup_logging():
    """
    Skapar loggmappen och startar loggningen.
    Loggen används för att kunna följa vad scriptet gjorde i efterhand.
    """
    LOG_DIR.mkdir(exist_ok=True)

    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    logging.info("Script startat")


# -----------------------------
# Systeminformation
# -----------------------------
def collect_system_info():
    """
    Hämtar grundläggande systeminfo som är bra vid felsökning och säkerhetskontroll.
    """
    # SUDO_USER visar vem som körde sudo (annars tar vi USER)
    user = os.getenv("SUDO_USER") or os.getenv("USER") or "unknown"

    hostname = run_command(["hostname"])
    kernel = run_command(["uname", "-r"])
    uptime = run_command(["uptime"])

    return {
        "user": user,
        "hostname": hostname,
        "kernel": kernel,
        "uptime": uptime,
    }


# -----------------------------
# Nätverksinformation
# -----------------------------
def collect_network_info():
    """
    Hämtar nätverksinfo:
    - ip a = IP-adresser och interface
    - ip r = routing (t.ex. default gateway)
    """
    ip_info = run_command(["ip", "a"])
    routes = run_command(["ip", "r"])

    return {
        "ip": ip_info,
        "routes": routes,
    }


# -----------------------------
# Öppna portar
# -----------------------------
def scan_open_ports(quick):
    """
    Listar portar som lyssnar på systemet med ss.

    --quick: mindre output (snabbare)
    annars: mer detaljer (t.ex. processnamn)
    """
    if quick:
        output = run_command(["ss", "-tuln"])
    else:
        output = run_command(["ss", "-tulpen"])

    return output.splitlines()


# -----------------------------
# Valfri kontroll: SUID
# -----------------------------
def suid_check(limit=20):
    """
    Letar efter SUID-filer (kan vara intressanta ur säkerhetssynpunkt).

    Vi tar bara ett utdrag (limit) så att resultatet blir lagom stort.
    """
    cmd = ["bash", "-lc", f"find / -perm -4000 -type f 2>/dev/null | head -n {limit}"]
    output = run_command(cmd)

    return [line for line in output.splitlines() if line.strip()]


# -----------------------------
# Argument / flaggor
# -----------------------------
def parse_arguments():
    """
    Läser in flaggor från terminalen.
    argparse skapar automatiskt --help.
    """
    parser = argparse.ArgumentParser(
        description="Automatiserat säkerhetsscript för Linux-system"
    )

    parser.add_argument("-v", "--version", action="store_true", help="Visa version")
    parser.add_argument("--quick", action="store_true", help="Snabbare körning (mindre output)")
    parser.add_argument("--no-network", action="store_true", help="Hoppa över nätverkskontroller")
    parser.add_argument("--suid", action="store_true", help="Kör SUID-kontroll (valfritt)")

    return parser.parse_args()


# -----------------------------
# MAIN (startpunkt)
# -----------------------------
def main():
    args = parse_arguments()

    # Om användaren bara vill se version – skriv ut och avsluta.
    if args.version:
        print(f"{SCRIPT_NAME} – version {VERSION}")
        sys.exit(0)

    # Förkontroller (så vi inte kör i fel miljö)
    check_linux()
    check_root()

    # Starta loggning
    setup_logging()

    try:
        # 1) Systeminfo
        system_info = collect_system_info()

        # 2) Nätverk (om inte avstängt)
        network_info = None
        if not args.no_network:
            network_info = collect_network_info()

        # 3) Öppna portar
        ports = [line for line in scan_open_ports(args.quick) if line.strip()]

        # 4) SUID (valfritt)
        suid_results = None
        if args.suid:
            suid_results = suid_check(limit=20)

        # -------------------------
        # Utskrift i terminalen
        # -------------------------
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
        if len(ports) <= 1:
            print("- Inga lyssnande portar hittades.")
        else:
            # Visa bara de första raderna för att hålla terminalen ren
            for line in ports[:15]:
                print(line)

        if suid_results is not None:
            print("\nSUID-filer (utdrag):")
            if not suid_results:
                print("- Inga resultat (eller saknar behörighet).")
            else:
                for line in suid_results:
                    print(line)

        print(f"\nLoggfil sparad i: {LOG_FILE}")
        logging.info("Script avslutades korrekt")

    except Exception:
        # Skriver full felinfo i loggen (bra vid felsökning)
        logging.exception("Ett fel inträffade")
        print("Ett fel inträffade. Se loggfilen för detaljer.")
        sys.exit(1)


if __name__ == "__main__":
    main()
