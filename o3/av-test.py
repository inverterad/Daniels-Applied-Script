#!/usr/bin/env python3
import platform
import time
import os

# Kontrollerar operativsystem 
system = platform.system()

if system == "Windows":
    print("Windows upptäckt. Scriptet fortsätter..")
else:
    print(f"{system} upptäckt. Detta script är avsett för Windows. Avbryter.")
    exit()

# Definierar EICAR-strängen
# Använder r"" (raw string) för att backslash inte ska tolkas
eicar_str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Hämtar användarens hemkatalog (C:\Users\användare)
user_home = os.path.expanduser("~")

filename = "AV-TEST-NOT-DANGEROUS.txt"
file_path = os.path.join(user_home, filename)

print(f"Skapar testfil på: {file_path}")

# Skapar filen
try:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(eicar_str)
    print("Testfil skapad. Väntar på AV/EDR respons...")

except PermissionError:
    print("[!!!] Antivirus blockerade skrivningen direkt!")
    print("[---] Din AV/EDR-lösning fungerar.")
    exit()

except Exception as e:
    print(f"Kunde inte skriva filen: {e}")
    exit()

# time.sleep för att ge AV/EDR tid att reagera
time.sleep(3)

# Försöker läsa filen igen för att se om den finns kvar
try:
    with open(file_path, "r", encoding="utf-8") as f:
        fil_innehåll = f.read()

    # Om koden kommer hit betyder det att filen fortfarande går att läsa
    if fil_innehåll == eicar_str:
        print("Filen finns kvar och är oförändrad. AV reagerade inte.")
    else:
        print("Filen finns kvar men innehållet ser annorlunda ut (kan ha rensats/modifierats).")

except Exception:
    # Om ett fel uppstår (t.ex. FileNotFoundError) betyder det att AV har tagit bort/låst filen
    print("Filen kunde inte läsas!")
    print("AV har tagit bort eller satt filen i karantän.")
    print("Din AV/EDR-lösning är helt fungerande och skyddar mot kända virus-signaturer.")
