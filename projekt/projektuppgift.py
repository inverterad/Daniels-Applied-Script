#!/usr/bin/env python3
"""
Security Scan Script

Utför en enkel säkerhetskontroll på Linux-system:
- Samlar in systeminformation
- Listar öppna portar
- Kan även samla nätverksinfo och leta efter SUID-filer
- Sparar allt i logs/security_scan.log
"""

import os
import sys
import argparse
import logging
import platform
import subprocess
from pathlib import Path


SCRIPT_NAME = "Security Scan Script"
VERSION = "1.5"
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_scan.log"


# Kör ett kommando och logga resultatet
def run_command(command, max_lines=30):
    result = subprocess.run(command, capture_output=True, text=True)
    
    cmd_str = ' '.join(command)
    logging.info("")
    logging.info("┌─────────────────────────────────────────────────────────")
    logging.info(f"│ KOMMANDO: {cmd_str}")
    logging.info(f"│ Returkod: {result.returncode}")
    logging.info("├─────────────────────────────────────────────────────────")
    
    output = (result.stdout or result.stderr).strip()
    
    if output:
        lines = output.splitlines()
        
        # Trunkera om det är för många rader
        if len(lines) > max_lines:
            for line in lines[:max_lines]:
                logging.info(f"│ {line}")
            logging.info(f"│ ... ({len(lines) - max_lines} rader utelämnade)")
        else:
            for line in lines:
                logging.info(f"│ {line}")
    else:
        logging.info("│ (ingen output)")
    
    logging.info("└─────────────────────────────────────────────────────────")
    
    return output


# Kontrollera att vi kör på Linux med root-behörighet
def check_requirements():
    if platform.system() != "Linux":
        print("Fel: Scriptet fungerar endast på Linux.")
        sys.exit(1)
    
    if os.geteuid() != 0:
        print("Fel: Scriptet kräver sudo (root-behörighet).")
        sys.exit(1)


# Skapa loggkatalog och starta loggning
def setup_logging():
    LOG_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
    )
    logging.info("╔═════════════════════════════════════════════════════════════════")
    logging.info("║ SÄKERHETSSCAN STARTAD")
    logging.info("╚═════════════════════════════════════════════════════════════════")


# Samla in grundläggande systeminformation
def collect_system_info():
    logging.info("")
    logging.info("═══ SYSTEMINFORMATION ═══")
    
    # Hämta den riktiga användaren (även vid sudo)
    real_user = os.getenv("SUDO_USER") or os.getenv("USER") or "okänd"
    current_user = os.getenv("USER") or "okänd"
    
    # Om det är root men vi vet vem som körde sudo
    if current_user == "root" and real_user != "root":
        user_info = f"{real_user} (via sudo)"
    else:
        user_info = real_user
    
    # Logga användarinformation
    logging.info("")
    logging.info(f"Användare: {user_info}")
    logging.info("")
    
    return {
        "user": user_info,
        "hostname": run_command(["hostname"]),
        "kernel": run_command(["uname", "-r"]),
        "uptime": run_command(["uptime"])
    }


# Samla in nätverksinformation
def collect_network_info():
    logging.info("")
    logging.info("═══ NÄTVERKSINFORMATION ═══")
    return {
        "ip": run_command(["ip", "a"]),
        "routes": run_command(["ip", "r"])
    }


# Lista öppna portar med ss-kommandot
def scan_open_ports(quick):
    logging.info("")
    logging.info("═══ ÖPPNA PORTAR ═══")
    cmd = ["ss", "-tuln"] if quick else ["ss", "-tulpen"]
    output = run_command(cmd)
    return [line for line in output.splitlines() if line.strip()]


# Hitta filer med SUID-behörighet (kan vara säkerhetsrisk)
def suid_check(limit=20):
    logging.info("")
    logging.info("═══ SUID-FILER ═══")
    cmd = ["bash", "-lc", f"find / -perm -4000 -type f 2>/dev/null | head -n {limit}"]
    output = run_command(cmd)
    return [line for line in output.splitlines() if line.strip()]


# Hantera kommandoradsargument
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Säkerhetsscanning för Linux-system"
    )
    parser.add_argument("-v", "--version", action="store_true", 
                       help="Visa version")
    parser.add_argument("--quick", action="store_true", 
                       help="Snabbare scan (mindre detaljer för portar)")
    parser.add_argument("--no-network", action="store_true", 
                       help="Hoppa över nätverksinformation")
    parser.add_argument("--suid", action="store_true", 
                       help="Sök efter SUID-filer")
    return parser.parse_args()


# Skriv ut resultat till konsolen
def print_results(system_info, network_info, ports, suid_results):
    print("\n=== Scan klar ===\n")
    
    print("Systeminformation:")
    print(f"  Användare:  {system_info['user']}")
    print(f"  Hostname:   {system_info['hostname']}")
    print(f"  Kernel:     {system_info['kernel']}")
    print(f"  Uptime:     {system_info['uptime']}")
    
    if network_info:
        print("\nNätverksinformation:")
        print("  ✓ IP-adresser och routing insamlad")
    
    print("\nÖppna portar:")
    if not ports:
        print("  Inga lyssnande portar hittades")
    else:
        for line in ports[:15]:
            print(f"  {line}")
        if len(ports) > 15:
            print(f"  ... och {len(ports) - 15} till")
    
    if suid_results is not None:
        print("\nSUID-filer (säkerhetskänsliga):")
        if not suid_results:
            print("  Inga resultat")
        else:
            for line in suid_results:
                print(f"  {line}")
    
    print(f"\n📋 Fullständig logg: {LOG_FILE}")


def main():
    args = parse_arguments()
    
    # Visa version och avsluta
    if args.version:
        print(f"{SCRIPT_NAME} – version {VERSION}")
        sys.exit(0)
    
    # Kontrollera att allt är okej innan vi börjar
    check_requirements()
    setup_logging()
    
    try:
        # Samla information
        system_info = collect_system_info()
        network_info = collect_network_info() if not args.no_network else None
        ports = scan_open_ports(args.quick)
        suid_results = suid_check(limit=20) if args.suid else None
        
        # Visa resultat
        print_results(system_info, network_info, ports, suid_results)
        
        logging.info("")
        logging.info("╔═════════════════════════════════════════════════════════════════")
        logging.info("║ SÄKERHETSSCAN AVSLUTAD")
        logging.info("╚═════════════════════════════════════════════════════════════════")
        
    except Exception:
        logging.exception("Ett fel inträffade under scannning")
        print("❌ Ett fel inträffade. Se loggfilen för detaljer.")
        sys.exit(1)


if __name__ == "__main__":
    main()