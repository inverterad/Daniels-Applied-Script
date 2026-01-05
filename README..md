## Övning 2 – MD5 Hash Checker

### Uppgift
- Förstå hur hashfunktioner (MD5) används för att verifiera filer och lösenord  
- Undersöka begränsningar hos rainbow tables  
- Träna på praktisk användning av Hashcat i testmiljö  

### Lösning
- Ett Python-script användes för att generera MD5-hashar av slumpmässiga numeriska lösenord  
- Hashvärdena testades mot rainbow tables för att fastställa en lösenordslängd som inte kunde knäckas direkt  
- Hashcat användes för att brute-force-knäcka hashvärdena med mask-attack  
- Resultatet dokumenterades för att verifiera att samtliga hashar kunde återställas  

### Resultat
- Samtliga hashvärden knäcktes i kontrollerad testmiljö  
- Övningen visar varför MD5 är olämpligt för lösenord  
- Ger praktisk förståelse för hur lösenordsstyrka kan analyseras med säkerhetsverktyg
